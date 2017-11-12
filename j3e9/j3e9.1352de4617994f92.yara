import "hash"

rule j3e9_1352de4617994f92
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.1352de4617994f92"
     cluster="j3e9.1352de4617994f92"
     cluster_size="1722"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre daytre trojandownloader"
     md5_hashes="['00dddfdbad6542762f00b9160cdd9268','01e38a313e11169cdfd1ac937f78aa64','07522f1a7a3183268e0d6c9aef829f3a']"


   condition:
      
      filesize > 16384 and filesize < 65536
      and hash.md5(4096,4096) == "e29fb9842fe730ac9a333170b91adfeb"
}

