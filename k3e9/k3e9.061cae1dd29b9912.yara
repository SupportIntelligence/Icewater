
rule k3e9_061cae1dd29b9912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.061cae1dd29b9912"
     cluster="k3e9.061cae1dd29b9912"
     cluster_size="3"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor peed qukart"
     md5_hashes="['5daf7e3a383b5c200458175947561c2b','68024c4993bad39455a8ff924e87c1a2','a302e47ac9a7a0b0cad645fc358f840a']"

   strings:
      $hex_string = { 7b027374726e636d70000000970276737072696e746600006f6c6533322e444c4c00000000f0420000f0420000f0420000f042004f4c4541555433322e444c4c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
