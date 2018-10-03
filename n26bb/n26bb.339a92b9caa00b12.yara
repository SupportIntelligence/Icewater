
rule n26bb_339a92b9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.339a92b9caa00b12"
     cluster="n26bb.339a92b9caa00b12"
     cluster_size="28"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="jaik injector malicious"
     md5_hashes="['bd7c396994091fcd3b2f0d49da94a3594dcecff2','a33ea3b993191717f4d77e9add8fa97f4e490647','260088ae4565deb69f24e558810171007ac465be']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.339a92b9caa00b12"

   strings:
      $hex_string = { 87956ce7ba5103eeb51bebbe0235e0de9f5ce2508ed479cf8a9e1de3d6b8120474df5875629cabf45e6594c4aa3b89e548a78b57f31f221a32e8c6e97fbfbb0a }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
