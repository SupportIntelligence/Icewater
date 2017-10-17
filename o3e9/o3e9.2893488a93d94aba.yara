import "hash"

rule o3e9_2893488a93d94aba
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.2893488a93d94aba"
     cluster="o3e9.2893488a93d94aba"
     cluster_size="884 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="installmonster malicious installmonstr"
     md5_hashes="['4c307ffb6ed2b7d477e466dc73790e10', '02396e81f93c8280e0428c6c95132714', '3ac8d2c35a34d2b0917a516453049afa']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2842624,1024) == "c11901c4dd26367d9df68014efe963c5"
}

