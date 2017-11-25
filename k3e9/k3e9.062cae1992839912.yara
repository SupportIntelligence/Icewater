
rule k3e9_062cae1992839912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.062cae1992839912"
     cluster="k3e9.062cae1992839912"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qukart backdoor berbew"
     md5_hashes="['074e066bb0ef98cf9f9d11ca9b28511e','aaef705377f6c121b78a5ab51d58e69e','f2b35cfcb281a19b7c866f04afd825da']"

   strings:
      $hex_string = { 7b027374726e636d70000000970276737072696e746600006f6c6533322e444c4c00000000f0420000f0420000f0420000f042004f4c4541555433322e444c4c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
