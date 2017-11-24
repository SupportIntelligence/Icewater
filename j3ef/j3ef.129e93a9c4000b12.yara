
rule j3ef_129e93a9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3ef.129e93a9c4000b12"
     cluster="j3ef.129e93a9c4000b12"
     cluster_size="8"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious kranet auno"
     md5_hashes="['6719fa9a10a7b160259fcf1238031f1b','693596d361bd521f755216827500c8cd','fb54cb70310f094a08e105dd9ffcacb5']"

   strings:
      $hex_string = { 392d394135352d4430464246424537454344337d00006b65726e656c33322e646c6c00004973576f77363450726f636573730000536f6674776172655c4d6963 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
