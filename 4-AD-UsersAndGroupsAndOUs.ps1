<#
This script will create users and custom groups. It will them add insecure ACLs on them.

TO-DO:
- Be able to create own usersnames within powershell
- Be able to create own passwords within powershell 

1. To create the users array run the line below to generate users from a wordlist of f.last newline separated
cat f.last | tr '\n' ',' | sed 's/,/,\ /g' | sed -E 's/([a-z]\.)/"\1/g' | sed 's/,/",/g' | sed 's/, $//'

2. Run the lines below to create passwords
num=$( shuf -i 2000-1000000 -n 1)
pass=$(cat /mnt/d/Downloads/rockyou.txt | head -n $num | shuf -n 50 ; cat /dev/urandom | tr -dc '[:alpha:][:digit:]' | fold -w ${1:-20} | head -n 1000)
echo "$pass" | tr '\n' ',' | sed -E 's/^(.)/"\1/' | sed 's/,/","/g'| sed 's/,"$//'
#>

<#
#-----------------
#- Documentation -                                         
#-----------------

@ First we have to disable AdminSDHolder
https://petri.com/active-directory-security-understanding-adminsdholder-object/
https://social.technet.microsoft.com/wiki/contents/articles/22331.adminsdholder-protected-groups-and-security-descriptor-propagator.aspx
   
   @@ Enuemrating AdminSDHolder
   get-adobject -Filter * -Properties * | select-object Name,AdminCount | where-object -Property AdminCount -eq 1
        Name                         AdminCount
        ----                         ----------
        Administrator                         1
        Administrators                        1
        Print Operators                       1
        Backup Operators                      1
        Replicator                            1
        Domain Controllers                    1
        Schema Admins                         1
        Enterprise Admins                     1
        Domain Admins                         1
        Server Operators                      1
        Account Operators                     1
        Read-only Domain Controllers          1
        Key Admins                            1
        Enterprise Key Admins                 1

   @@Disabling AdminSDHolder
        get-adobject -identity "$(get-aduser krbtgt)" | set-adobject -clear AdminCount
        

@ How to find basic, valid ACLs
https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule?view=windowsdesktop-7.0
    $acl = get-acl "AD:$(get-addomain "lab.local")"

    @@ Constructor for the "ActiveDirectoryAccessRule" object
        [ ActiveDirectoryAccessRule(IdentityReference, ActiveDirectoryRights, AccessControlType, Guid, ActiveDirectorySecurityInheritance, Guid) ] 

    @@ Add an invalid ActiveDirectoryAccessRule ("bruh" is not a valid right) => Error message shows us the rights
        $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $(get-aduser b.nobbs).sid,"bruh","Allow","00000000-0000-0000-0000-000000000000","Descendents","00000000-0000-0000-0000-000000000000"))
    
    @@ Adding GenericWrite over Administrators to bnobbs
        $acl = get-acl "AD:$(get-adgroup "Administrators")"
        $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $(get-aduser b.nobbs).sid,"GenericWrite","Allow","00000000-0000-0000-0000-000000000000","Descendents","00000000-0000-0000-0000-000000000000"))
        Set-Acl -aclobject $acl -path "AD:$(get-adgroup "Administrators")"

@ Basic ACLs that can apply to users/Groups/Domain
    GenericWrite
    WriteDacl
    WriteOwner
    GenericAll

@ Extended ACLs (like DCSync, Force password reset, etc.)
https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.extendedrightaccessrule
https://wald0.com/?p=112
    @@ Constructor
        [ ExtendedRightAccessRule(IdentityReference, AccessControlType, RightsGuid, ActiveDirectorySecurityInheritance, Guid) ]

    @@ How to Add AllExtendedRights over Administrators to bnobbs
        $acl.AddAccessRule( (New-Object System.DirectoryServices.ExtendedRightAccessRule $(get-aduser b.nobbs).sid, "Allow", "00000000-0000-0000-0000-000000000000", "Descendents", "00000000-0000-0000-0000-000000000000") )
        Set-Acl -aclobject $acl -path "AD:$(get-adgroup "Administrators")"
    
    @@ Adding ResetPassword over Administrator to bnobbs
        $acl = get-acl "AD:$(get-aduser "Administrator")"


    @@ Enumerate GUIDs
        Get-ADObject -SearchBase ((Get-ADRootDSE).ConfigurationNamingContext) -LDAPFilter  "(&(rightsguid=*))"  -Properties * | select-object -Property Name,DisplayName,rightsGuid | sort-object -Property name

        Based above, the cool acls are
        [DCSYNC]
        DS-Replication-Get-Changes                    Replicating Directory Changes                      1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
        DS-Replication-Get-Changes-All                Replicating Directory Changes All                  1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
        DS-Replication-Get-Changes-In-Filtered-Set    Replicating Directory Changes In Filtered Set      89e95b76-444d-4c62-991a-0facbeda640c
        [Others]
        DS-Set-Owner                                  Set Owner of an object during creation.            4125c71f-7fac-4ff0-bcb7-f09a41325286
        DS-Validated-Write-Computer                   Validated write to computer attributes.            9b026da6-0d3c-465c-8bee-5199d7165cba
        User-Change-Password                          Change Password                                    ab721a53-1e2f-11d0-9819-00aa0040529b
        Validated-SPN                                 Validated write to service principal name          f3a64788-5306-11d1-a9c5-0000f80367c1
#>
#-------------
#- Variables -                                         
#-------------
$DAcount = 2 # Minimal amount of DAs
$users=@("b.nobbs", "l.rees", "a.mcguire", "a.booth", "e.snow", "a.lynn", "r.murphy", "m.hudson", "s.swan", "m.snell", "m.doherty", "c.newman", "a.andersson", "l.farrant", "e.roberts", "j.jackson", "r.hale", "h.dale", "s.locke", "b.coleman", "n.baker", "n.williams", "s.driscoll", "m.tennant", "j.weston", "r.cattell", "j.vaughan", "l.sherwood", "k.atkinson", "m.simpson", "j.cork", "a.hunt", "e.thomas", "j.darcy", "i.appleton", "w.robinson", "c.darcy", "j.eddison", "a.jacobs", "h.powell", "b.johnson", "a.wooldridge", "g.waterhouse", "e.mason", "t.walsh", "j.williams", "j.driscoll", "m.ballard", "k.purvis", "h.franks", "e.wood", "g.whatson", "j.eaglee", "n.pratt", "p.hogg", "d.nurton", "c.harris", "m.hill", "j.victor", "c.howard", "e.stevenson", "svc_1", "svc_2", "svc_3")
$passwords=@("anthony98","goodhairday","pangit1","rabaya","babycool","lexa12","staci","robin95","abi2008","vatech","goku13","darknes","bigballs1","love890","angelamarie","doughboi1","t0r0nt0","24042532","smocky","19062529","bible777","cherry45","quocviet","nishad","140978","020258","saramichelle","leo2003","211003","teamotlv","240531","dancer321","lagusanaciega","gucci99","lafuga","helena3","nov1126","290678","n4th4n","mynewpassword","trojan2","anaines","ricardo2","raffles","rexell","JAMELA","lala831","lifeteen","garrablanca","070704","NAzyoKeMXFA9NrCYBtt4","q8nWSfqq5aqLkS8KStYB","BFvchKgldR9kwfO1OQvz","NhorcUn8pNpvBgeapuuM","d1W4zMYKkrUlwAm16xl7","0usrBtKTuFn1V9uGCBTs","tJYqrbio16eK66Q9T8KY","9CWxEd73E5DUEnCkJmsD","td7N3Y4wvgEndIOyQsOG","WrQjR3XyggKurpqqpwNc","TQfXvPgmQNfzvMvhzFyS","wLOuBCJ3an1BPZdaCqV7","OehODqsZHhKPNbiNEWnD","m85UqvSQUAIr99WeYUpf","lQbvr2JBUvNrz5N9PwUo","XauEZHRyQ28oPvcRBk9R","q8ABdo2MFZUw8yJHmti4","bSGsB4BURht8T8tnNq6E","QUe7DLZSEbaErkJygDit","XNNruin4RnBOoUpue5dA","PtRZ0Km0PEQnznY8tlAY","5gXR1LoGJkNfaxWHe4xK","w1ZA160UmZCFC5SmEJTo","9B7c3oeUCEqPT1XppF6l","bRRr6iZkiHeRV8z4zeEc","JCQAviX21iKcpoxIFkb1","HsZfUDlAJIeDCW2M6tFT","qX77he1tgb392HWZqtqp","yxpCuJBkQsswnAzdZU2x","jqwAJiGdtptzvqR78HUO","hA80vFopi8jiEYsNPbAV","SQwr85ClXqr5xgeXGFwc","6lqM9eqfCeVrsTYpvEV4","m5UXQ7TKokeSbk0vUTIF","EdL39J6KI1KVwugZgNQC","TbdLIkEd41xpagqh5ivk","3uZXHwrgB9Mdybw6iDIJ","uYbohblc8cDHBtOXUYEA","QaSPClgjcL9J4mr6CwhK","eIK3WhI5POrA3EyXQL9E","8wWrYnTr21hZShnQug1I","d48M4pHmHvjfwZCQCVH5","wJoXpSWkGb0M1yg4brzA","TsLFqMMZTz9odrSjmNrT","wdxfqjv21nYBIkoK2Clh","AcvXC7FxEfHKSWLUKIYD","QAfAyyOKpE0NpyS9jtKS","glZv7o0WN46bdGnyFQdj","n5chB8OA7A70QcECvmo5","RmC0PROdsI0u8xvZgIFc","oVr2izJVJTxvWLM4rMeQ","owOIm7vFjwOjy9xkOIWb","8znM5WHY85WMhTknlFeb","whCa5Gn4IhfNoHyXk2t8","o0Kn8GMDusruBAh7PHGI","8yVOTz4k4XqUmPwMi4YJ","e7jeml5swMCyW49CK3k6","YUavEn5kAlX8XYbt00ht","M05c6Q0G2e0uSm1EOdUb","TsKU1grxK3aBcvLpuuzd","80MBHdrAz3qPXjrA1QAP","NRo0kQaYysNmqdHCBEZy","68tViOAMo5EajWn0f4z9","y7pqk68ypjGuUMMHdkeY","lvsvYIh6j4YuJdjzHcG5","RTpnze8T5r9KYjRwIYun","TNiUyTlFWrx954Rzqgke","pXg9VPYBAvXppiD2DtXu","slaD9TNVmuUmI6O5mtCP","LyUDzEYKyoY8KhggDs2H","J1tGqJ4B2bFCJti6WsL2","gmMX0zr6MW4m9h877H7a","IggJ5inVKXYcsFiTCj2P","grLV4BdHgEIUkPrw4Rx0","6DwWHyXke5l7uvkk1m5l","cnFaDlYYC5fIgouHoYMc","sT8bv6yrpYqVH475Em9W","UYpvapgoZrq2DfJgNGZj","EBd4PtACWrizPhB4pFe6","VBXSSFTqMQ1hYGGHILKC","mTfnjfLMcssDiZ9j48ri","ggNul18xARQNSdiR1cto","23UDXD0DZzEx0yQ1ByvL","eZUK3W8qtli6DXsB7ZGE","twvRCETb5VKyL8byoXJo","WELX7ezESRs73R06CL0v","QO6p8jTAJWg7s5NFqiVE","pjghDb4wLHgYV4EtnyUD","9KGYqyLFuyLCxdtEEPE1","MO5HWJX2STzN43YRtxYZ","cILhDjF9JwCpYAnlQTyW","xPex2eG2SaMbpBwBIuch","mEcsfpJ470I6dxY8FXUE","rnRV4kt2f3wik78uVTdg","2tHTR2Z75AFPodYGzHG0","BdG0xNNTYby2hdKGKc0O","Imfd9LnAL7OLIltsluqJ","pcH7Yd5tGF6PHgyBlNKP","NojiWZcDdhrW7asu6Tdr","p9nZwY0h5uJKbCuOnE4B","26aGIQzIVN2WLfSbAjie","2hcmOa1zcvIy05rDAC62","MC0HK04Rtn46rvxnW5Qc","dOme1wr2tO3q9SdpXs7T","4p3GVzteQnCeWPWmqmCy","hAfz7g76b26XLjqsJk4N","QWefPtp7Ei3E0UwFDek5","A2ePRMfRv5pWIujyZo4z","xZLYlBMAyLKewBbmQjmr","jXiYdvMhCXYhGJHv5u1U","YdLlXZE9wI4DcSdRf118","R4CFU1xs7lZ3VvjEbMhI","p4y6lqGPxdvRnU4issXQ","Kn97dYWgvmpU0t8SqDkF","4BECO6ZCg3ojXp5y7D7N","MNaXZKw8PpjRTyCuwJQp","G6UACcdADjfFuKqXhwZZ","6ykSguysaTB6n5rZzq5C","N4X7eOJQMX7rG0ckGP6e","nehIMdOn379BI0UDkpiI","BWt4hSChPSo6XpMjwLMK","wixteDd9QipiHtYCJsKs","GmmIDrPLyDUtsk4xT6IW","j0jxKvvOYsS53V7ZBL8w","LVbMEfjGOEo32qW6SImG","3g9wHFw65comzoRtrZTy","lgluqXAIgYg7dHFaQpqb","DtvUPgQZ1LZgG4mtmbAM","bbMB0of143k3hC7JTBs8","iDjV0EsXDOyM3wou0yEA","gUwaDl2ompDJlRtqXA1L","rnbDXm2rJw5c1ZtFa8nN","vfqy5hgKmyanhcP70brP","esYO20wBX2eFSIEgCAP7","gmrwMAHOnj8t5VwqEZuL","DttGwnpijvglsppLTwPh","MnWH5mCvQhWS62pMo4nD","Y4DC86nOTlTD6eBIbdGU","Rb7CP9xMQJNI7FPXH79j","25gu8WnMzCIC1hIPso0n","43ylUKbJixDzHrChRIeK","S4FIpIouC7cLNbOdt0oV","t5ufWgfBY4AVog1zajbU","NSiIWgiTnMgSQcdTZVM1","YrwbqQg6fYIkQYnuj2Tb","EXRMqJBicwm2bL2xhgEK","VWjHiGvGKEFYaabhqLHK","jqMjCsy3c6MfcimybZDX","0tUAl6vYFY4B2x390IJU","Fb3p7Ls6vk2qHRQnP3R4","dY8tr8IMCyQ6yAdD4jgI","KhLvjzkDHFCmbszflljz","XTbADAi8jeDcevOV052T","7STokkr6ncyownKL45gG","Ia5wumpR7X4ipK7x0Wfx","k26YBPNeHktaxwbhXnml","7ThJqD0MKZQF757dW1nK","VAE3bBIyNzSuYyKnxYIj","giLaMiL01rOvSSYOkBNw","omRrXhAqVKUaxaYAx33L","nvyWSKuSAd2cszhzd3Ny","h25yx77KG0DutHwJ46fq","0MSbRJvYdvyk6LnloImF","ETjN9TBU7ZDAGb6SwTsv","ftZiMP043NxgyP4t5Aul","jKXcfPgnBUvWL3TexVKR","9LmyvSHNNjkMxixJTfgz","PNpbunOs6P3clcgaL9xN","gAqBMlWXwVbaRYImtjvr","fULTMuRjvk6yk4taCtiP","hZdnSCDlyqWh1mh3MMN9","EDSPGtgmpNFyQvKRUxQN","hzzCyJQIPQ35eKvbHtNP","XgbKl0HaM9lMogO7U9gM","i4PqUOvdoWwZcQWbT2s5","hsoHPmC1BSO04MaIL19R","rs7xNtUOqy2FrSIM5xgu","6b2q8xGAIM8ZY2zfRswr","3qxhEELZX3OqSiyg2q1a","r5myVy5tWPdyZS7pVrxJ","ALbTB5wyV5uiO6uBhhG4","wLYsY8maMkC7xAiBcxz5","UF49y6LNBmvyMPBM17cp","4mWUuF0kucBhpvfWnQvp","PiU3OjNWOp7vCxRQRfzg","oE6omUG7yBubhfNSxx5q","vAezDjc3k5QfSqEsQGUR","Cqzmjar1xl0NKzCdmgUh","ENXJjbfMFuFEQ1BdoNfL","x7kbANGu6iM8WkMy6m4l","7ukTDZCMDJZLEL8rJ1rH","ZiH81Y8VY57y8P6bzsJ6","7cGbPkyrlAhJA31FbvxX","3GpYW9id5cDdb9DDkfxB","d6rThaznjmYVI3eU4Krw","rG35YhUEcq9iNrflrgJO","K1yhLMxS9ELGM7Ekpp57","AIPPtm6iBtaq0NwqMKKj","np9em7hZugwdMxjp3K1W","IBPDxBaE9l362Raojgoo","x5OkZTA4F0AGncvZipe1","v1amV6Xr6dDlLP8yzJkC","LOqRHvewlpNnaSR2ojQk","DWZzhJix9SIJLkUqyd8e","jhiynK2P0EEMsALQlmdn","7KwEbdAHptb3Vgu1Gwsc","6DrDvkugNAEbV20az49n","2adXe29MkMcUBhzr4wuS","pX3Zp4d0b2RaZHQ739Uj","G5aoT7p3ASKalT2s9tY4","PuX0qyGfL5cTQCUlfYD0","5DRlv1a2kxxlamzd5pZy","tRmFo5dWVGxZs6OqgsiX","IId4MdC2BgrVGND2Qbbj","rxKHTUvGvwAdfnl8ahWu","2QmfsBnDzCB8S0fvimv5","HfLFWjNWOL32xl9uzPJO","IuY5kIRt17GpdiFfAehM","G9xQmdwfMgIdAPSfIO1p","nI6zUlwVXCJXYHFuyXma","5owGPS67ZxhLv4FKQibc","PuNWEFV3f9m1qf74cPrU","2mU9ycznBuru2ejXmS1n","Bfq9TLWSuNp9AhZ8lERj","7nBEip4Ua8OXlJY3WY6p","rBgDTR392SZWmdsnoAsP","1hPgMgwkSddGEnmbHmCg","HUXbnlK3YNhw9FflbiX8","fNrsLsYJGD2spcuZCr9G","lFQrs6fBiEx24IqDpEZV","dfZpqzCDSofkgE8yckER","JJ30lMu0XqeUxD8svyqn","DBguY0tiibXs74d11du4","oSsZQqFeb1WipcmGQ3pX","WXjultJ42HeJVsM6q0dR","LdwdkmgiZDpdKh9uqWre","gtJscx2k4DmR9EQC8hfq","9fzTW07cR20ON10cEeBY","o5gAfNrnx5oYJrSPfUdX","kz5i2sEni7sj6UUYMcXG","35ZOT3p6ob1FrgcRbTwx","gatnx9yReWyfOVDW4stt","eEgMVsxnx3zsjk3nkCMa","nv7JDhsxPgGQp7XrlK4C","Yf1VbslQVlJZIASRSMjN","gcuKN1sLbV6L1XmBcSSD","gsBkfz7wCKpyptjaNiwh","B9zowpBs8ateZgEt73Lm","RxeA0v2brrAVjwvMvYaC","iZxyX1Efl75tHGyD5BZp","qqXKVftf6mdZInvdd8bV","Jep4P3ewpiyBcVQFrrMC","evOlFpV7KxErhqWmplbU","EIhtFhKLUGbmDP8MtsnH","YxWRWG4jIaoheBm9agSJ","lOwi0KWDS7KSxD7DSEge","uj45DUFdXmILmElh786e","jC655AUixmVAw9F0bXtM","vvMgKr40d0NPFohxejNk","dr4jir8g3mxDdP5xNGVv","3KVaSW2Ha1OZ8FI9GHMo","A4mbSHV54Yst9RpEDLuo","ePjOjqMIPtABPOIZ6SLL","BfZQMxIQ2VM17vQiYKCd","18rbXC87Y7hvtRm9SUXx","A7oWYthZ2xnzsiYBkLKq","xhniSVQQIELDQhRPCWlf","vtC3IYaOsiHaPGI6qEoT","2QtxlP4RjLEPqhsuntQC","2UfIPZTsnAEiYSz4lLEF","MR7qkkjoLsTqDfaO85KV","ocPTPacweSHR2Rak9jCV","vGG9wi0SkM6HONuqp85U","vnxPoyZIsGY6seogeUIv","ZtCqwYyHAcSXWKlrBn2I","pK9zMP9XdI1fFsS4rW1C","IFumgvep85EajluePAXe","yxt94OrNrznZPbCGk4y4","p1w1D0UlSYZvruGjdl2k","6uyzJq7vI1Gc2l8OtqHz","R01L1TPPt7eGaldzso91","W03OaoiQWgfGKRK6D5qQ","EMeSqtVzdX3Ul79hlP6v","EmhS7KY2EDY28D4Cohf9","QBAgLCy7SfVVnevPxQfE","5cFeVoOoJzPOv6fn2xYo","DFLQLGF1USAXV05SlKIz","3qqYO1JrwVGksvOrQxYF","r4lRFoIsPaAjNW7iMIEl","WanuyU1TZaba1FDMmRWD","50miyGG3j0JQl8iASDK8","Lh7tYJYEqjQ2OfWjd8NM","mrlY4VszNxrpvP87gw3s","MFNPXLBsLVZ9w9zKtBDm","02BFuLxWY9zs2pqhb6Ul","alggM1XHTsuy9eAZx0od","U4ZDOCK2Mto59pKWmpO9","4aNwjtWMjqjDxjBSO77Y","EQ35RPiNacmkxSUMdvee","x5iWVtjbc5fbrofySaHg","fRsTY41LtJmvZIkWZdLh","WdDpJ4s56cnqdLNtCPY5","ihEGvhTuUu6z6afjGov4","emfiAv527cB61SyIxvHa","ChWxCGFP6rXXAuTTPU01","wwgSrgC7BM1h4seiOyei","p24gZMKOUMrv9jFVxz8D","I1S1Pae9myG7G5M2Gigu","jyzxGCj9OjLlixLEg5S4","prEyPNtfsZ0Iw5IQGI8P","Z2oHsVGgNDPOZIpTYP49","wtZOx6Gkt9UBTqDayWUs","dtjfy0oPN1TRs8kQsSUp","k2H9eb1PVOZuRSAvVYHM","mRwyoXYeNDeQxRoTfOxc","R3R6mTyYeJGidn2C5DVE","GelWGpVC9KEezgOYoC2R","lnSPDofipTkXyXV6VN5r","LckmmPlEOclQJqVA5lLf","aSidyM3wNc23NcVCAO9J","ZYh4zaAjlAZyupPMp5Xx","ul1mbYg6SyibwyjnpRh8","SKPsVuqOP7WMnin6Lu2L","rJaHp79c8dFuYJUNsbYr","wcUeTWnoQVdIICs4Fpo0","k9vwXsgwBq85F9JBYjzf","WOYDpIBJlkKtWgL9fYaj","m1nzNq3Ly1Gyt2IAJkip","QnCPkyqsBGt7b3SKeJPW","aEd4ZrhiqjVQO8G9u2uC","vjOwX4t2HpQ15Gaq9ZLz","OW3aku3GWwTqQ2BdVEDs","S8z86t8KqlOw3oXBTo2G","TKukMPbCN14HcF669V9b","gNZqP9iifhD4BfDmeVmO","mEkketGE261UsK8QZa17","oGq7Ml7KWXEfEvCZS76m","KMuRBYsYRH6kJhU2TlKL","butizoxj6eL1XaIdmu9X","PA5QQuzaddPzlraIuMBb","8sBVhyKKmdfll9gdidUJ","klwFW2a4CYcefvs2xfGt","pqnVtDsYqAZeJtzEsSH9","mXbqZ3qMOCp7gLZ1pj9k","zyTQCLL8KNNubkyNcSQK","xdeeiCduXXwwVaqOqtvl","LV0YVoLTE4yqxIo8C4TA","7tlfQNj4V45gQeOycKBF","zFXm2jZytUWbXHr91a5z","L2WK9FSC5ZGfORwn7xlm","3AKnMWX2yhIEBRGRkxIO","A3QMvxG5kwiPNfPHfKdx","NtICubXg08BC17CDJ7gT","PvTwiIj9oPUh3m7sVY6D","NEfW8jtckpG1kn8ft9rD","g6H2AP3yBWPfWtKwYsja","r09yOk78GGNc37pSaHcw","jxcZWF6d5gI0ORF1wZqa","b1wNcqLAlktOHEn3Aumi","tZ5PuQqzOevtlhsYHa47","Sddl1RZE7QK795txP0if","cKZ1KrEDrNj3x0GP8YXO","hTJ3wzqPEClPfk5a3zxw","1myk2HMF4k2m1MpjVRRI","gDSUt09bHhuNH77dn5Sz","RrxYuQB3gAF96fc9pIVw","RePa39W9WGpmt17nO3Y6","VvTmCjT2VzQbPidICbaH","5n1ewI5PwqHT2UcPdn53","AzIpwyZHSkgWfUCmdHyq","jTajWgg21EiOUakaISjX","oi3zzWWHLfdWaRnScRC0","B328TWSIC1QAHmugzG1P","xTApgiPY4iF23ln6p3cR","Z86tCPrHTrUuo5LCJ6PM","Hl2iigkRVrhzk20yWqrO","5NVTDcLuV64odsjdh1Uj","Om4FY3yCGYHKPba8xaTy","Pe8yItXuEKxyMut8SyU1","yPth3ZMmqdweqaFNZShz","XriC0IJ15ZBduL4beJL0","wouWXIEgdUmp4bqWsTuQ","RlP46Yjf5zUEFNEgVDdW","1xAtI5UCka8dj92rT4RA","2n5lo94KypIJKtkdgkxe","zFqRGH1m6bmJWgY8No5f","WEZhBXK2E0CYtsv1vmPv","0rdVLDAtFmWZAvtRb27T","EIADhN4FSnw3Etm1bVnx","nmZed5hwoQWjYdrPaJiQ","hH345m11hZEuyxkreJ9h","Yo48m8TRYC57lhLhjrww","8Lkx07uIxPiSbTLCfjdU","lXULKLFPuowZce9ZlJsf","KAqBgRR5DR8gV3rw6V5W","4IaeB75H5rZDjGHHisEu","WExmNf1PTXBHNcVC8dys","vdNZimSHJx3S5Ov46Unq","SaagnHxDezRz49BH9R2R","DueyzJKcc1wxXUY51s0y","5LjmXPizI3fV4LyUy1wq","rU1TvXXJGHsW0aRTrrMy","fYqylfYaclneb7iU1Zux","AIKbGfoGspjpI6V008Ae","vD8AVgQY6nnScWIPgFFs","vuXGvMmc8R2QWYLsqYn5","yhQ17DqFhXH3aDBsTTNV","Yiydr1vJ5Q2poCswf58Y","SaRPQEspWvsXJpAQYeqc","K7CKAyfscDgss0Wk4otA","fqCGWEItAtRTNp6PhP2r","GAtjQWeMXiTmbTgqLAhS","6UxIK8FD4riRJuy2BiiZ","2DKmcKsEDQ0DncjDC1en","c9UWb3hZhPW4Mm8gn5rF","ENvPAVUHRpXDwQp5SmYx","DQAqpgibIUZXHe2b0Y3F","s9yITZZ9RNyhaZm2ujyw","025Wt4nywQzihUHbWuJd","o6odZw7LiV72hdJzaWwT","BVkXu1RK8lxFNnZj5CYH","PrhpLxopXiBi3hADsZHj","5Zqf13RHRuBln9zjGB2V","KqvZo0UigJsR77DxU87O","aKdNUJxHnCZRzA7iCe6r","XpEK83WNMxv7EprYHCMk","X84OeqYl6mnpWMBOB61A","RcSqUwMED4A5Cj0LsytJ","dLz8qBwV2YDnEkUTf7a4","z9ybapFX3oruZaHffZni","7JpuPzo7lEIubc2ZOj73","qaTAZjQeoaDIy0Gs5cTn","Ez12gvIphqOar5vGtY99","kJui7Dr4dqthz1ajacWD","Wr8TLmAjwCy9qisaF4L0","se48qSQJnwyuR5riBqrT","zlxwA5sPyBaIYuMwyrPK","xWTVX0NCJMD9pCm2jSBd","vdzQKgaEMwxEVCJAcY6D","4smqpuZnpoUDfY4lXWFY","AW6rfVn73QHmcKaTVeWz","YNOqg9VwwUGn0iwYYaFP","qCnkbToZEqdg7WtWm6gM","noA6ose23L2xOKpt1tRz","bozTSDnyiDmtcK7yMQbA","vkm3yRjvBjVMiHgshlWn","vvpHKoWwN6b8DOsBSnfI","MRx0s6PeDaWxlkqP9wlO","G52UaFVI8RfbY2FyOEXp","2So8yiT3Nbyd3sNtRJ1O","ekqokx7tWU7JyxabseAb","28kgEYFazlQtiqEE936v","q5BAYNJB6mRmtOA3WDp4","NJ7FhlRheoXMazvatIlf","uTdaOMvr28moUOiLiBgw","xMrXBXAZNP3diaRskdlN","3R7qfQFOZhQlUF6hObTu","VPm8H4hHmCp5lvtPZqCE","EXsJ15U9rLqXw0KXwBij","KRJoGMxqEfQH02dd0WqP","gCMENeeYSySWdKjaCphL","Ii0YHU5mo1wiCBVHmobN","jexdyXknxgduZwm10Kil","QOZ94PJ7yPerHkWdve6H","AVbzkseDYRT7g7qTY95o","KwfWa1OrO2PspGJ1K7QA","uZIEGPo6dPBjZb0VHOCE","NrI5HXjIcQ0ekE8u8D3T","NmvQWUrgGcGqLjchC85M","dZMfONKpssUrdjZSdkrN","ECriIH74kbSdMR8mZftj","406Bye8pyttWvi9wPRrS","ZdAE6rnvVJhYL43z3uBc","jzxW8on1gUvSn9ETLBiS","cojUteq4maqh11K57lAQ","W4MnLZclJZeZJverkrci","go3CgRkUOhaZR7FFfdQj","p78g7s2zoUgOCXUycQ5r","azW9tDo0xOdOukTtGd65","xMfCJ9vmfw1j5cp5xOih","Ns7rHvwVgXRHayFb9Jzp","QapWSdZnT3dflnpN2EHe","EBMa5MLDIn6dAW0EhSgH","xnPfP8MJgNtxVy9eQh0S","vYDbVENCj4R9B19Lu3WX","9tWnBvIjLGtQTAhSfIrj","5F8l2ahbXqd4bW2PHDlV","wozlxS6mMJMKSNFZi8yY","tzIcs2Y2Uxi4EUqJALmk","bLULgQHxqFaYcOl1xVIu","FrbsFdvuEqFow2BPjljw","cotg5G28lClMkYDpRoVG","xLlO8wnGDkDTe1qL3hTA","GWE4Q0aedENzxdtBbzwo","J5J47Ujk9KlAe81dzY17","tzD4TDD9CoPU0lf6Ig3y","1k5jMvh276HluSSNgBg6","OaMHfaakySxApLGEZFW0","GNgiBO03KU79Ubrwrmtv","CSyfXNeC4WjXojl0rmNT","8MYsYV7gmoLOGD5RWhPe","27Rshr8gqML57JGqcJxS","WzIN1efjPvjboZ5Anhhk","rEFTjyw9qS11iB1Wbqxk","rbJDUVNJGU5ywXzAh3WR","u77NlAr9n8nQyI8I1XCs","bJo0G1vLz819GSMEVCZX","gRlGUXnUEDFJQZjGmJ0J","Fi2HaUzUT4llgIon8kWC","D6ZmHIn5aqVHTWQDhskR","berLYX9r0lZuisvFf33P","yBAhy5uK3zD7NkvVRHbm","V33BiRnH6743O65eKoUP","kgBb0UxINulEjzgCRiEl","NZt0KI88AvzobFs4lech","IQXeEJ0Xm85x0mFb2MbL","sgYkE33KAowuul8LavMk","IBUu60hDpugoYEXnfEQw","eIxgjybnv2SPstLiS2ha","klibhd4x9ryp5iZQd4YK","XdiZ0csVpvoa5OLR71Qg","2yJO5qp5TUQEGDYjpjs1","uL4x3uJF0AdQMpn26yyP","bZhbqmMUeA8Cm92LOvLk","gsSmOmUDUShVQZTjNHS4","feQ4LSCTXTDbOnbkSPRc","IoykJqpV6MkvVnjS2wz8","Luc3mWzQ8a7YsF9ae7Lo","aPqpFX5LOgVqsOoYu2oh","axx5spW3w8XFN2rFECwp","0Hb1VT1oIi1aMAcBwxzA","dqJ0mOOWacW9G9p7PDBW","TxLDpxGO9wS6qsfZMbs4","ZAQCwKTJzjWEQmzzRR8C","h1TEad1Dx7CfyaG37TxV","6cgxOIRY9ZIvPNAlywtv","iiy8VNiezdO0rk10emwL","JVhDVQUd02OY62R3i8e2","5N0lY8KYLbtL8Q8AVLlT","83U4Gr2B1nG6aEpnlPWE","Ey1HrRk9Tl59WutQfiim","DNOSRzWi0rIeisDP37T7","JNYeNO9wZG09GJ4XdCBh","tidkYpRkDCqrb2evKcag","h4d3FbOpp9BBbiA3RvgA","nABqf4az4D6VTxXFNbyO","AAj3QTJAXGplMp2lWwvx","qgceUGgnUy7dXb409T4W","okBbS2ge3oOv7pK86lAI","QHT5qWL71RTaokwUkdOw","UVtiUNYTvM37DAr3HXpY","K3ulnBWezXu3MIpgTWXh","tqJ7z4VO5bifCW43H78w","jJMIQhhzGkTwpjRzbD1Y","Bl0IRNaTzFVKgorCRzQ6","cgvqYqSYJtgfKiLriNvi","wbDa3dFDzgKsZE1GevuM","Jduc6Cxssdzn9mBOpjmY","ROE5QXD6eIn9iA8jKev1","xQQsahm71EvzTSpzQVDd","E0znfo9bKXSqkDoDcXnQ","PIX67l22hLYtDcrWSI5P","2uj8OKqwQU0b9WpI0953","sdas6xNOBtZVgXjeJUKs","iIefJ1D53tiTC9tl4zfM","LOkcpnXPZdku8htvr56X","3MaYApB6XCXXzBUGF0Ko","Da7Dvij6uo4uAlco0bme","IrnZEepmmNPIvDOxNxAV","oseGYUyETEl7BZ5nrnJ8","lxRRHXsbfjjiDnTXKYhy","bjywpE9ywSIoNRCVYrB8","26ZzyYf8QUezGYztiqm1","bCIt0DMNj2qku5bMoUZq","auUjMBZ4F8yaMz9VZNVm","tFrMqZ3kwHTKm48bKPQx","rN5YyvjVnpENt33Vy3XW","SDlX4Vyymzs69i8zR7Ur","U1eCJEKFHuQb3Y6MpDAU","3tWJHobvZMOFIYxUOzXH","dGU4xtAQH4go9MSUXPne","EUEnW3cMEWtoMFfinbht","MBQkh2Wxq2mz5L0hioKu","nzE9COfxnnU8mAxkRHRW","zlME9tPQDAlfpS37mF8n","a8XqkqFjF6mjfjacKpYQ","AXrD5ZpvvBgQzQQuuHUH","8Veafr7ne1OAm4332ayt","rR2pPEhZAnqoY8n5vEsg","4ynNPlgiyRkleSNXUuyx","yGskpCyYi2Uxh8Sl4P6J","TGGOhFiGRslYpxwnMKkM","6RDvpev0WsaAMJrWRjU1","ctZ0Z0TqfZne7TOoOJJl","DQiHDrIK88IhwSrnMfcv","i8m0EQAazli1eB6moqW5","QjiFnSC8ePCOvHnEpVkb","nSSKmYrjl4fnYnWztiZi","22Fe69VObVbTuFlSw6uS","ChlvqG7zkzEpYwM5S5Pm","USnellNscQZsGyDaBqb9","cuXRrk7QBGxcIJW3Vl8i","5lMoCAqbZKfaaIVAQdAM","nxP37cAvLMXpu5Cf1hF9","OqeHrypIpj08nR8FGktU","qMeIhs7fbzBjyYomhTyN","seYnzLTm6UPtntxYQi8u","bU5y8z2e4G7dgeAGimQm","EdvTpOruOpGxDegOrGBs","Wn7DCCOLDjKsvpWgSrPo","Ocwq8DYUWhgHVUJwGruw","UG8WZTGF4hs2U5DL4bGP","yC3EcyqPr7VdONahQFFd","sp33RNpk0yzI98pD0YAO","KI0nqS2eNq8KJsRtiHlC","NgZiVNzmjqVs2HPYsYtz","XWIHkQU03ZIUF0L6oLut","IxmdLiJbtnPiIcT4ov9f","Ppad2SZ9TbeYx3cCjnBi","0EDJd3xNkoUFpKQ8baL6","jYfOnnpHVQkrCNRJLcML","j0ADpxFXSVVzlzxG1loj","JktDtShggT54HrDEtQuu","kg3V6OIrGV5QWvelE6Ma","quWYAp3McrWi7LIG22iX","rrUhp4sWZasdcMoyTIoN","RwpdXdBWnnNIwV2og413","uV8qdLjpKmWhAs1A21mZ","7fv3fxMQDZ1dbTXPMDOG","EdMP1hLnH6NDAErVuvXF","O62hELSmoAN2jox1EpBT","otXfm8Ckg2BBsbXXmLEh","fVwM4IJUUiocuuok0rAK","rPtlVKU9drAxpI5pTx8F","h5nJGp6xrSXU9yAHvBVH","D5IbHn7TT7xhMjU8PpDv","7saUhlaUD0ofqH72z9bq","awcpORfiiF3Q9bAoUxpS","1adVJD1p0QTols3iAMkU","urTRcEMqjlYVfvNpPZLY","NJRZN9coxQiIGh5t7SUI","XUxYNuZPbrhTRVW5vm8Q","m1z0WoCjFXXrdoxZbfYL","nqIbym8mSum1OBwM3tFy","Ip47uuL958a0jefV6EzB","LpveDQ6TwMmdkQ8XW3lR","IC0ub9XEKzKqolpx21TG","1XNOvy9ulrAh4CtApSRY","8DwiHYxO3WzoOgDf99Uq","jYwJ1iAc2i0dQ8i2WdjJ","eRsMVTthx8GiXSzBZBCM","0E0b6jQJKkfde6SCQsXe","8T792vFJd7gRsenhoLKD","SYVjVyhYru5VKM6x0Z55","vgobRJdDuhfYYNzR86jR","z7aVl93nqFQ57TCtzpsN","GM64AkMg0q9hjqawENZ0","n83ZCqABlV96MsWfw5eR","dCDiQ3sL7msE2iNAFptk","jnli9pyIE7t4aw9gIz1E","uZT8vzPKnI38pmLu30Uc","679TJc2MNWh7Ah9nxR2s","7R7udmJS7LFwICsQ3McM","BrGLyKsPnOFykz2bLR1d","kdVf16d7HhOC1l66ACIl","BdgzydRKMvG0Ug0Abr0O","cfaVs53Wp1J5b7e2lBDM","fxOzPGbzbNPDGwTCM0Jo","5htCOTN6ajcA0hnsM07D","2cgcmHACIKHWWrdeBpAS","HNVPy5nszCAUG7jxIVRz","fKoADtXPWTTfPnblwwFc","gmpi8zeF0o5eMEwpGETr","PKjkRUEbxjnSBZeQ8aBl","UC56SlxdQi9nmJtw8Yxp","jFO7eWaIJZbXBA0PX0wJ","1pjnG8bmz0rJpLbR64L8","qe1fWcwC6rgZLpVaFYHb","OTxmtcvBR4jiWjAcAUJi","0V8YIZ7M38s4eGbqG20t","CnZEWk8NyjxY855R31aK","HUAEMdTOR4HaDUK6sHRf","lARWwcpJbrVAOgZ9AOTC","ZtvP2uT2wLNGRPfVRwr8","lNiPnPrxSQLUYZdyFJDz","DOsI1juqhb0GfpyRKrV9","BxD0zpOatDlZFBgAERuR","rRSFfIuYspFqE6LhADno","YJQeg88gSoGQPg2n8qU3","RTH33cYmt7MP1r6mkMqD","ctGzAyXN7kwim9psj46P","6Cq6p59aOhj4WbB009xw","zG1vlblgO0hdvjkfUFXO","ZbDApP5m7fA23UkNeDuz","ldpwJFqsB8CJDDLyVnNJ","ksbbOCQAIDk6zu4VsFWJ","V3wljPYuVEHT2ma9zdyq","bfyOkZJjq6b5zzZaYVZE","K2o2xsR3lZp6ffFAagRu","D8rhE4YMnTJkVin7inYb","sGrQbpCVZ4KlqzsPoRsF","LNPvn4dpyCA2OaGYnt7Z","5PkxBbiyzE9srW9l2FLl","qjO9Zj7KqKJwTaGnZeJY","SHTFl4GDJyCgwGWDWXLb","Cy5wtj4PIlsucTiYE80S","vSiPQmWmSjh6iQAq3FJr","r63ySIRKBkUoSt1gJ16y","yVJ7ypy7r6wtajC57H2r","fTR09QFifX0MSFFsFHzb","ugmm5k1r7kI8qIrgKu3x","rk48SVvmTidIZ434Nb87","5jOxwYHByHTthBLDbNXq","7wqH8QcpP7GlHKyJv6t0","sEe7s6hfwx2XNX3KyKPz","nwkTp15gRGDEeDpqGe40","J7dIr06DxmDGILHYtt6w","HZPjdKPqegHvjROWJbt6","2eQWLb2f5OmsOozc3Uoy","TIhyXYXPSUPg5Fk2RwuQ","VodowRbWQTPZFkxZP747","YeQjjGFuSIMVZTj7eToV","VmfC9Gg1wIiPLtPGxyqS","fOOzFD6HIx6kKekV0wiZ","dvmIbxDAGnls6lgFh572","NzR7Cc85qQ2ybZJwkQMk","6rKpHQIxeFsxbEGWw6E4","ig3Bv1AI28UkM5DL70yL","pqZy5Gp8NE4qt03bM1Pi","1qLlSHBvrQi3kJE8OFiY","C94qCMs2BbAo9bwAX3fg","krgaMRZVG0OYkMOn9md0","q7UItYAOxzF26HTpVfKe","MASof2pG3yQNYqs0EAcs","tSP7kBjIXn5S2gAlByU1","6qcVQRDnoyNyyvj4aAwK","12WFulPSNFZs1KRuR4tC","JOvKuOfklsIFAMuBbe7h","H9liA3juu5PjCeXazXvV","WIQzWPsSnAlNEZfalILK","fiK1Kz2hkUhisStMBHpS","djjRrJtzTFvetMhDFUUH","ttiXdxbzr0eAAMMLehI2","dRHnQ2YNKfM685zwNavz","pE0pBZrlU49rvVqt0yXM","i4j03ZON3BYghC2vvF0L","bTyAEkipeK9DQFQ8QLRO","gjXLHW0KLPJvHb55NueQ","3aCDovAer1dhSITHq4PA","h4CGLcj0CeJpGbEfZCjS","gD47WM4yLTvXJAL09gr5","1Cynu3iFk0zmJtdXJ1Qs","lwgcMD4TylglOEI48bcG","o478VRbg7TVRRBSmGPJQ","8qxFagCH0KUQqmp3DEsQ","t34WayAJKDP0efGAzaYf","xA1TxNBou4DkfGkDhpOs","VB9PPRji85Xt1TS1RtaR","jZr753xsPynMb0jQMyoY","pcxHb3Qy0xvc6XndTeL5","aLFOPXxwE6KWhJ02qbAc","quCH0hrVGyWyrQdJpUxQ","IUWD1nbBm4K7SVTDZq7L","T9J6tJSrbsA6MN1CDQey","R118I5IyarQ7RGXgS4sx","AXDdoLwGvlA5JC0z0vVo","MVMMCuEP0rxJkqDnxtQQ","IZcHVk4tmHSGX19lp2RR","WcW1KJirdRDaSSCKl1lh","BVwcYXTS4acEhUhG3hJx","DeJ1mOM2WTp2MUaC60MB","TeCe0Jnik3nVVnKrPzJE","7TX0uINfcoTwp0mKhNWC","wLbQpjloBTLRedS847J9","y3sofk3cy7lXkxekEHFJ","fDP6B86TNtcNUyvBn1E3","qH2iDsswFhuazHxnXrJJ","jo5le1UlhrRu4EpIvGyM","7kEWp9f7yh6xsq94Rz8F","PA42bvdXHKhDmOMLONNw","sZpbHAcmFUIrONVQj41i","w77KjFVHN13EDecdUuC5","LUWpO42QWqNnGTabdrDn","lU5elZNP1AKSTKgLS0l6","egovPP9fc7MiAaVCgQug","jxBIqlqFXRQGelxyKsiG","H00FHEZ68zqDrK44WDjT","9gkh4bTmtLRK76US2yf7","S1dbhIGDrJFp3qedfNVz","8XaGSIT2sBGKGClGKyVB","IXDmwhnlp5a3WQXDzhzA","yySqSUk9eXioA0MEMuNG","f3BgUH6odac8by3Ba25C","sHGObo8PJiGYwXYDBW5g","njxJrcVAlq7EpzyjteSu","pDy2bKLswEFCJlU7Oqxb","4mn5haHkauuAAiVq4aAp","vHeFi7L5Ab2NVZp4nUWS","9C2BK18SrWueQpm4vQFv","rsBTnkOyIrItHVvDLmaW","atSjTyZM0UDCTTsqcgQb","cWBNss7Q3zvbDTd7vzvG","1H1ccMp5aFiXX0ew7B5G","7b5qgxd2nPOT0BWnpMfI","EQPC3C5ZY91J4MINq3Jg","ZIU9497TcQ5E1DjJrA3t","o3mCDoJrnQt8Fjg6LmNL","dme8s6de6gcqoyPN4J4o","wURaESoGi3p51DDAdei5","qSiWvBvFNlooSJDhG7GO","8Igo5bxciiCmXuUnlOQp","RHnGQcARhf4O4DyTOkGg","ogQgVNOBATunIEmxDVL8","NSyCmYOJMTFDU2XQ52M2","UZ4ThQkLfoWXxDyVf5JF","ollLoQdBTzmnactHnrs5","AtMiMqnqzEhqPEAbhJoC","akKaevhNJU41D7zg8MeQ","Cou9JZqYY7xnR9Xd7BzT","NxzM6AKv6uJbzgXIwJSV","7wf8ftgjEbxfkLtee98u","8H3mXvXO7JMCJx6Cxuhi","PUJY5bw0raxreNtfIAqh","8xcEGsFlnHnwUkWBlHHk","SLKtLpkHj7KeQ9D3APm6","BALERewr7k2ITjO5QvWO","o0AOyoE9brrkWiWmilPH","6aRlJfF6CVH2AHpu8azb","a9DseeZF5gt92XbyrqlF","MkfIMbkLkj0h224qVZBs","EoJFDLKTeJBelkO0R9FF","jKddzK4OszyIm7fNYMkW","0emQmMplrycnm3cCGq1D","DQNhuWj6KM1x5iFlcv2H","OaV2zVmPCCPnI8wU5Yw3","Pp4fMTR1qzVexMIvT0lk","enYB04gjlepAVH7r9zEh","aMs94qzq2uSX6ErBinkG","v90N1b1MjLa896EhQ9B0","LPGPdI4mAvu0Bvxfvt5A","nqjVMsgYaPNM3U6tD7M4","A68q487qHrk5AoeYA3Qh","0rUM4akEFrwDcU1a6vUG","AblFI3PGFDHZ0Wd8H6H3","ORcoco5XXBj0HZtiRyJi","ZRJcuFNUINvil1ayUlrQ","uA1lHedYd0PmTXtoVbl6","sghRWUT0hTUjnNspIFuP","HLtdKbQchl7rQLUesJ5Z","Cu3viXMsaLmNWa0ohYZz","Jton5e7fx6w8zilcG7J6","jpTW9AofpOWxLAKAwzfj","mt48YYf0R3Ed7RWsHtYP","b2xWwbtI9t8tUS0jPNPv","JIRPy8u6cUb36VFzwyFG","JsfRvmiN3AwvH8AyE1Vp","m5KSGQdHxYqe04aGcUfw","JQP3fGI3TlNPujnpJ7RM","7hofqxV4Brq1aGE4B52M","cEPDIDsr6GSo5xVVdHUf","6wBVpRqhemippgFszmPH","GwQFwtr3TEReO1SVF7nU","OBCh97V1gthGZUqQ13FG","yZEDnmyxjABKSAuqbyTz","5ZxVkoGwZaI6RhURNva4","cXFFGolOyqcAIYbNmJCT","yeuRZWwnwEhEN2aVxYkR","kXq6h51mIhOtHF75hRm9","QvSfHKzBtvHI7vSDq4Dl","Zaar3eq9GVHcpyhZU82Q","rj5LpmcifTesRi3MDMqT","zoz7ZdOSvzb9JRiU1Cqx","uHxaMNPFLmncdQBNyoy0","rdqa48ylVkav6cHcNq7O","BU9hSMioOfE4SjjKqU2f","xIOO0XQxO6UmEXk33ZDn","kQYYZVQVHgrgvCVDdg1O","DJYJqP84F2OgiEOxtFaM","oEd75G4ltrlSTDjurCC6","3Ro950GgJqmpuPlpQlD1","8LV6PShgqgTYoUPCM9Io","i2DRptt8FjIt7gVV15FO","f9ysSVcA35lXMWkX6I4p","edl7hHygvGaBEAni62w1","8bvfTDHyvIQkSXTG7WWN","oTtmapUBTs9C0jUuorFb","pohqJ26nKVXt0dr5Wx3a","rLMeYDEDv3M62eCeRFnF","dtVlTwhEwaTJkuLXIq65","XIhWvX0H2ivDEHwczupc","4I9OeT8pn3ngB6n1KBFP","r3WjyYrycMiwrFy1jQeO","SHcPw2d4NBlOH3G9E9s6","zsPIbnVLRnXjrIy7AKyV","aV8m1CCtClmiTodjQlux","6KcZMRWQfMkIC2ayqElj","b1s3A2tZD46A5GPgorFE","pLgX39R67hSSisGwKjt7","ObiXP2tQ1qskan6DVzRE","vNmgKGabGmhaBrdP4uVX","D6sF4PrMvadCntMETGbP","GkfZWKXolfpiqzSr98hI","oiyhlOc9SwPvB2TIAWmz","c7vYgnBEBjPLVwdpmOM7","U8TxRC5FnHholDOi8iLh","NLpwKmxjkGobVU7qBXCP","7SWwf2z76AHGnTKfxL0s","QiS1jkl8id52Jddt0weh","ycGfLRzDOdRq7pTRZBtA","TjRYGK25Sk42QIzzIxFW","zfWucTEiofmXYaC2CnFz","1N0VzE0gV3ahTIOhOoy3","8JdiUzYkAj4jaomVFxIN","AUtevemfAcSYSk7ahnCS","6wu5zxPx6nyCrVq9fO5E","mQDXoWiHTuaZFMAXZNkg","TG83eT0bbgcqnGoQfo0a","NoINi2QPXo6qhsOOC6E1","GoWMymdB4gvz51PZqv68","MXPwx3KLNfTMngvfiWu3","Pc3FHHjDIRXz0H54TDdi","ddj6Ckht5Kl43dQ2OwMC","oGoYdy8qSKYNnHMol0qS","Lppybcuv3exki1JBjmcH","tyn8ddiY35G6dNdJCPjA","gYtSuRlKN1clYOsMwgYu","8h6Pw08tK337cbCCfMpr","9cjlpW41fwEU0LBn61yy","naurD9oBB0Mr5c277U7Y","wweKh2hFBlpXcQJUduDm","tg038OQQg09IcTdR7vFL","3jJDLLnjSnFqsgrU3ufS","rW2zX78UGpHLXkCUvfrb","6kCMT33pfoMQHmATHGKC","oQZl5h6Am0dCXDDZ48uR","jJvjsAojSMQctp2RDAlb","8CoUgOjFDXnB9gIj1Xvh","Tm8qMxGhn6jowzzUmRMb","ffk8vSoOeXs93RJMHrzV","wjMBFtOts0wvxGx8kCY5","fKNiU25MQTpum4WNKTZB","zaHNZ3NDXX2CuZ5Rx2TC","e18LuiHXYdGTq2Uu8vbG","4YahuGTIJtQ1BwBBAT7E","BEmrSxGINaGAXNOjMsLb","EL8LEsMOM2Q2ECGOSs3a","tYsbdsU6vnjlL66pUOqT","o7SOQTJN9cd6UN2L4Lav","2oZyEb9NdZQQF4VoI3Cn","EOHrQhHltExEycJuHwNF","XweXiGrO2N8AA76rpIVR","mXiFCm0llrf2kfiCfzUy","RT2CmABFMrJ9It8QTHYX","ZlkQ0vGMZmNzq3tDLqVo","8UAETL02O5O6D4akavzT","NLBGpFVTTBta0u9tZyCJ","za9a3qZONjRrFJk1HZbh","El21O7hCkP8IAqpi8CO2","IoKS9yLITccc2YcYWpxd","jguMbRF9MA732d9MlPFC","r8OMnNF2kxbM3bZC8OND","B2DimC648dYvwWMdabRl","1u3BIZZrTH1w46q91hyO","ncQ4QQBKfIf7mqwTDGMX","feSAn97UcbZChsD267pG","8WsAp7gLfT1h1bv0QNE0","mugtDiIqXOW6LBdOIn9D","rsyQqQsosvmWKoUC43Te","D9QpOonFB4cpJfhXcGea","tghPfAA1NN5EiiQyKh8N","BsRzJfBhKt41QxsKQmNi","7l0gxixePZeRoVem92IW","sB4glx9QoUTVKeviZuyd","ziYJ2UIeFIB6uUmu3RTk","TghV4gYKwWvM0whwAft7","BuO59j7yitOne9HnRHfo","tF6hdqCQQVJ3BcG6dmhj","DkXZoOQ6w1YDB9DgZC5n","CSuB2Tvp4LiwAjjknTxB","FrxlsiWFulkVZfBMzKA1","ST7rc9tEzlVXXQauLaL3","zj7LQY6MNOCEtPwxzDny","JtavT1mze2XAn87pjyVs","P6qw4UyUWTHhXgeYPqob","ZeTukPJIyVeJmuaP4Ruo","8LQ6ig7z0848z5uzkYkl","g8saClYrziVLKZfLAoLN","0IoVW7ySt2ccnq6OQYGZ","NMzN9mSjbBlm3VFnIKgi","1lTymbKUdVirpKUqmsRb","M6oi1pGxa6EEPH3xf6V7","qf3GWGgLK88Kad4GZYgl","v7IHqyHmobmMOF2Iae3T","V8jtDWY50y23xTD3pPyK","Y3p678QxuRdejAcPAbKE","U6WJoGhm4NjFVAvFgSNo","kh6ON3ep7M323Jtdz8vB","VDbxvcvEntIGBhcMRdrK","g4B0BjGJSqHAWVit0H1g","hb8Ojbig5Zp3JfuRtwCL")
$computers = (Get-ADComputer -Filter * | select-object -Property Name)
$spns=New-Object System.Collections.ArrayList
foreach ($computerName in $computers.Name)
{
    foreach ($service in @("HTTP", "SQL", "TEST", "EXAMPLE"))
    { 
        [void]$spns.Add("$service/$computerName") #void so its quiet
    }
}
#-------------
#- Functions -                                         
#-------------
# The Big Momma, add random shit
Function AddRandomPrivilege($controllee, $controller, $controlleeType, $controllerType)
{
    $privileges = @(
        (New-Object PSOBject -Property @{Type="Basic";ACL="GenericWrite"}), 
        (New-Object PSOBject -Property @{Type="Basic";ACL="WriteDacl"}),
        (New-Object PSOBject -Property @{Type="Basic";ACL="WriteOwner"}), 
        (New-Object PSOBject -Property @{Type="Basic";ACL="GenericAll"}),
        (New-Object PSOBject -Property @{Type="Extended";ACL="DS-Set-Owner";GUID="4125c71f-7fac-4ff0-bcb7-f09a41325286"}),
        (New-Object PSOBject -Property @{Type="Extended";ACL="AllExtendedRights";GUID="00000000-0000-0000-0000-000000000000"})
    )
    switch ($controlleeType)
    {
        {$_ -eq "User" -or "Group" -or "ServiceAccount"}
            {
                if ($controlleeType -eq "User" -or "ServiceAccount")
                {
                    $privileges += @(
                        (New-Object PSOBject -Property @{Type="Extended";ACL="User-Change-Password";GUID="ab721a53-1e2f-11d0-9819-00aa0040529b"}), 
                        (New-Object PSOBject -Property @{Type="Extended";ACL="Validated-SPN";GUID="f3a64788-5306-11d1-a9c5-0000f80367c1"})
                    )
                    if ($controlleeType -eq "ServiceAccount" -or $controllee.Name.StartsWith("_svc"))
                    {
                        $privileges += @(
                            (New-Object PSOBject -Property @{Type="Delegation";ACL="Constrained"}), 
                            (New-Object PSOBject -Property @{Type="Delegation";ACL="Resource-Based Constrained"})
                        )
                    }
                }
                $privilege = get-Random -inputobject $privileges
                Write-Host "Adding "$privilege.ACL" over "$controllee.Name" to "$controller.Name

                $controllerSID = New-Object System.Security.Principal.SecurityIdentifier $controller.SID
                $controlleeDN = (iex "Get-AD$controlleeType `"$($controllee.Name)`"").DistinguishedName
                $controlleeAcl = get-acl "AD:$($controlleeDN)"

                if ($privilege.Type -eq "Basic")
                {
                    $controlleeAcl.AddAccessRule( (New-Object System.DirectoryServices.ActiveDirectoryAccessRule $controllerSID,$privilege.ACL,"Allow","00000000-0000-0000-0000-000000000000","Descendents","00000000-0000-0000-0000-000000000000") )
                    set-acl -aclobject $controlleeAcl -path "AD:$($controlleeDN)"
                }
                elseif ($privilege.Type -eq "Extended")
                {
                    $controlleeAcl.AddAccessRule( (New-Object System.DirectoryServices.ExtendedRightAccessRule $controllerSID, "Allow", $privilege.GUID, "Descendents", "00000000-0000-0000-0000-000000000000") )
                    set-acl -aclobject $controlleeAcl -path "AD:$($controlleeDN)"
                }
                elseif ($privilege.Type -eq "Delegation")
                {
                    AddDelegation -controllee $controllee -Controller $controller -controlleeType $controlleeType -controllerType $controllerType -delegationType $privilege.ACL
                }
                break
            }
        {"Domain"}
            {

            }
    }
}
Function AddDelegation($controllee, $controller, $controlleeType, $controllerType, $delegationType)
{
    Write-Host "Adding "$delegationType" delegation over " $controllee " to " $controller
    switch ($delegationType)
    {
        {$_ -eq "Unconstrained"}
            {
                iex "Get-AD$controlleeType -Identity `"$($controllee.Name)`" | Set-ADAccountControl ‑TrustedForDelegation $true"
            }
        {$_ -eq "Constrained"}
            {
                $controlleeSPN = (get-random -inputobject (iex "Get-AD$controlleeType -Identity $($controllee.Name) -Properties ServicePrincipalNames |Select-Object -ExpandProperty ServicePrincipalNames") )
                iex "Set-AD$controlleeType -Identity `"$($controller.Name)`" -Add @{ 'msDS-AllowedToDelegateTo'=@{`"$($controlleeSPN)`"} }"
            }
        {$_ -eq "Resource-Based Constrained"}
            {
                iex "Set-AD$controlleeType -Identity `"$($controllee.Name)`" -PrincipalsAllowedToDelegateToAccount `"$($controller.Name)`""
            }
    }
}
#-------------
#- Settings  -                                         
#-------------
# Allowing gmsa
[void]( Add-KdsRootKey –EffectiveTime ((get-date).addhours(-10)) )   
# Disabling Password Policy
Set-ADDefaultDomainPasswordPolicy -Identity lab.local -LockoutDuration 00:00:00 -LockoutObservationWindow 00:00:00 -ComplexityEnabled $False -ReversibleEncryptionEnabled $False -MaxPasswordAge 00:00:00 -MinPasswordAge 00:00:00 -MinPasswordLength 0

# Disabling AdminSDHolder stuff
get-adobject -identity "$(get-aduser krbtgt)" | set-adobject -clear AdminCount
get-adobject -identity "$(get-aduser Administrator)" | set-adobject -clear AdminCount
get-adobject -identity "$(get-adgroup `"Domain Admins`")" | set-adobject -clear AdminCount
get-adobject -identity "$(get-adgroup `"Backup Operators`")" | set-adobject -clear AdminCount
get-adobject -identity "$(get-adgroup `"Server Operators`")" | set-adobject -clear AdminCount
get-adobject -identity "$(get-adgroup `"Account Operators`")" | set-adobject -clear AdminCount
get-adobject -identity "$(get-adgroup `"Administrators`")" | set-adobject -clear AdminCount
get-adobject -identity "$(get-adgroup `"Domain Controllers`")" | set-adobject -clear AdminCount
get-adobject -identity "$(get-adgroup `"Print Operators`")" | set-adobject -clear AdminCount
get-adobject -identity "$(get-adgroup `"Replicator`")" | set-adobject -clear AdminCount
get-adobject -identity "$(get-adgroup `"Schema Admins`")" | set-adobject -clear AdminCount
get-adobject -identity "$(get-adgroup `"Enterprise Admins`")" | set-adobject -clear AdminCount
get-adobject -identity "$(get-adgroup `"Read-only Domain Controllers`")" | set-adobject -clear AdminCount
get-adobject -identity "$(get-adgroup `"Key Admins`")" | set-adobject -clear AdminCount
get-adobject -identity "$(get-adgroup `"Enterprise Key Admins`")" | set-adobject -clear AdminCount

# Add some custom groups
$customgroups=@(
    (New-Object PSObject -Property @{Name= "Managers"; SamAccountName = "Managers"; Description = "Top level managers";RandomACL=$false}), # DA
    (New-Object PSObject -Property @{Name = "Operations"; SamAccountName = "Operations"; Description = "Operations team";RandomACL=$false}), # Under account/server/backup operators
    (New-Object PSObject -Property @{Name = "Developers"; SamAccountName = "Developers"; Description = "Software Developers";RandomACL=$true}), # Random Permissions!
    (New-Object PSObject -Property @{Name = "Server Admins"; SamAccountName = "Server Admins"; Description = "Server Admins";RandomACL=$false}), # Local admin to multiple hosts
    (New-Object PSObject -Property @{Name = "IT"; SamAccountName = "IT"; Description = "IT guys";RandomACL=$true}) # Random Permissions!
)
foreach ($group in $customgroups)
{
    New-ADGroup -Name $group.Name -SamAccountName $group.SamAccountName -GroupCategory Security -GroupScope Global -Description $group.Description
    Write-Host "Added group: " $group.Name 
}

# Adding Specific amount of DAs
$usersExcludingDA=[System.Collections.ArrayList]($users)
for ($i=0; $i -lt $DAcount; $i++)
{
    $da = (get-random -inputobject $usersExcludingDA)
    if ($da.StartsWith("svc_"))
    {
        continue
    }
    $p = (get-random -inputobject $passwords)
    $sp = ConvertTo-SecureString $p -AsPlainText -Force
    $usersExcludingDA.Remove($da)

    New-ADUser -Name $da -Accountpassword $sp -Enabled $true
    Add-ADGroupMember -Identity "Domain Admins" -Members $da
    Write-Host "Added " $da " to Domain Admins" 
}

# Adding users and adding into custom groups
foreach ($user in $usersExcludingDA)
{   
    $userGroup=""
    $userType="user"

    $p = (get-random -inputobject $passwords)
    $sp = ConvertTo-SecureString $p -AsPlainText -Force

    $roll = get-random 100 -Minimum 1 # Rolling for group
    switch($roll)
    {
        {$_ -gt 0 -and $_ -le 2} {$userGroup = "Domain Admins" ; $DAcount++; break}
        {$_ -ge 3 -and $_ -le 5} {$userGroup = "Managers" ; $DAcount++; break}
        {$_ -ge 6 -and $_ -le 15} {$userGroup = "Operations" ; break}
        {$_ -ge 16 -and $_ -le 25} {$userGroup = "Developers" ; break}
        {$_ -ge 26 -and $_ -le 35} {$userGroup = "Server Admins" ; break}
        {$_ -ge 36 -and $_ -le 45} {$userGroup = "IT" ; break}
    }

    if ($user.StartsWith("svc_")) 
    {
        if ($spns.Length -eq 0)
        {
            # just skip this service account
            continue
        }
        $roll = get-random 100 -Minimum 1 # Rolling for GMSA or Normal service account
        switch($roll)
        {
            {$_ -gt 0 -and $_ -le 49} # Normal
                {
                    $accountSPN = get-random -inputobject $spns
                    New-ADUser -Name $user -Accountpassword $sp -Enabled $true
                    Set-ADUser -Identity $user -ServicePrincipalNames @{Add="$accountSPN"}
                    Write-Host "Added Service Account: "$user" with SPN "$accountSPN
                    $spns.Remove($accountSPN)
                    break
                }
            default # GMSA
                {
                    $userType = "ServiceAccount"
                    $accountSPN = get-random -inputobject $spns
                    New-ADServiceAccount -Name $user -DNSHostName $(Get-Random -inputobject $computers) -Enabled $True -ServicePrincipalNames $accountSPN -KerberosEncryptionType RC4, AES128, AES256
                    Write-Host "Added gmSA: "$user
                    $spns.Remove($accountSPN)
                    break
                }
        }
    }
    else
    {
        New-ADUser -Name $user -Accountpassword $sp -Enabled $true
        Write-Host "Added User: " $user
        if ($userGroup -ne "")
        {
            Add-ADGroupMember -Identity $userGroup -Members $user
            Write-Host "Adding " $user " to " $userGroup
        }
    }

    $roll = get-random 100 -Minimum 1 # Rolling for ASREProast
    if ($roll -le 8)
    {
        Set-ADAccountControl -DoesNotRequirePreAuth:$true -Identity (iex "Get-AD$($userType) $user")
        Write-Host $user " is Asreproastable"
    }
}

## Add Preset Group ACLs/Permissions
### Managers
Add-ADGroupMember -Identity "Domain Admins" -Members "Managers"

### Operations
Add-ADGroupMember -Identity "Server Operators" -Members "Operations"
Add-ADGroupMember -Identity "Account Operators" -Members "Operations"
Add-ADGroupMember -Identity "Backup Operators" -Members "Operations"

### [TO-DO] Server Admins


## Add object ACLs
### Objects that may have write or be written to
$potentialWriters = @(
    (New-Object PSObject -Property @{Type="User";Details=(get-adobject -Filter {objectclass -eq 'user'} -Server ((get-addomain).pdcemulator)| Where-Object { ($_.objectclass -eq "user" -and !@("Guest", "krbtgt", "Administrator").Contains($_.Name)) })} ),
    (New-Object PSObject -Property @{Type="Group";Details=(get-adobject -Filter {objectclass -eq 'group'} -Server ((get-addomain).pdcemulator) | Where-Object { ($customgroups | where-object -Property RandomACL -eq $True).Name.Contains($_.Name) })} )
)
$potentialWritees = @( 
    (New-Object PSObject -Property @{Type="Domain";Details=(get-adobject -Filter {objectclass -eq 'domain'} -Server ((get-addomain).pdcemulator))}), 
    (New-Object PSObject -Property @{Type="User";Details=(get-adobject -Filter {objectclass -eq 'user'} -Server ((get-addomain).pdcemulator) | Where-Object { ($_.objectclass -eq "user" -and $_.name -ne "Guest") }) }),
    (New-Object PSObject -Property @{Type="Group";Details=(get-adobject -Filter {objectclass -eq 'group'} -Server ((get-addomain).pdcemulator) | Where-Object { $_.objectclass -eq "group" -and $customgroups.name.Split([Environment]::Newline).Contains($_.Name) -or @("Key Admins", "Enterprise Key Admins","Domain Admins", "Administrators", "Enterprise Admins").Contains($_.Name) }) })
)
foreach ($writerObject in $potentialWriters)
{

    if ($writerObject.Type -eq "User")
    {
        foreach ($potentialUserWriter in $writerObject.Details)
        {
            $writee = ""
            $controlleeType = ""
            $roll = get-random 100 -Minimum 1
            switch($roll) # Who we are going to write to
            {
                {$_ -gt 0 -and $_ -le 3} {$writee = get-random -inputobject ($potentialWritees | where-object -property Type -eq "Domain").Details; $controlleeType = "Domain"; break}
                {$_ -ge 3 -and $_ -le 9} {$writee = get-random -inputobject ($potentialWritees | where-object -property Type -eq "Group").Details ; $controlleeType = "Group"; break}
                {$_ -ge 10 -and $_ -le 99} {$writee = get-random -inputobject ((($potentialWritees | where-object -property Type -eq "user").Details) | Where-Object -Property Name -ne $writerObject.Details.Name); $controlleeType = "User"; break}
            }

            if ($writee -ne "" -and $controlleeType -eq "User" -or $controlleeType -eq "Group")
            {
                try # Assume Writee is User/service Account
                {
                    $controllee = (iex $("get-ad$controlleeType `"$($writee.Name)`"") )
                    $controller = (get-aduser $potentialUserWriter.Name)
                    AddRandomPrivilege -Controllee $controllee -Controller $controller -ControlleeType $controlleeType  -ControllerType "User"
                }
                catch # Writee is gmsa
                {
                    $controllee = (get-adServiceAccount $writee.Name)
                    $controller = (get-aduser $potentialUserWriter.Name)
                    $controlleeType = "ServiceAccount"
                    AddRandomPrivilege -Controllee $controllee -Controller $controller -ControlleeType $controlleeType  -ControllerType "User"
                }
            }
        }
    }
    elseif ($writerObject.Type -eq "Group")
    {

    }
}