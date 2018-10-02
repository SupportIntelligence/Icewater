
rule k2319_181096b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.181096b9c8800b12"
     cluster="k2319.181096b9c8800b12"
     cluster_size="83"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['008fd6e7c6c3a42430b62556e54f9db270c4ed5b','6f990ecef821d6e3e1630908490ac4258d4cea99','bc0c7de704ac9e9afa76aca70dee590da8e90ddb']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.181096b9c8800b12"

   strings:
      $hex_string = { 5d213d3d756e646566696e6564297b72657475726e206a5b4c5d3b7d76617220443d28307831443c28382e383445322c39362e293f28342e353145322c307863 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
