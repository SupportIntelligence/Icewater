
rule o231d_791d124bc6220932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o231d.791d124bc6220932"
     cluster="o231d.791d124bc6220932"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakeapp riskware scamapp"
     md5_hashes="['3fb99f377f4cbb0582d26e86ed916836fa9376d1','3c2fcdb5d32c1b5bd79d2f3b1ae9d43d182596bb','763c457925093c6f3f9768e58ede320a535344ae']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o231d.791d124bc6220932"

   strings:
      $hex_string = { c7bb55df05712632807ee87ffcf9e75fee8ffffad7cffbc39c6b1d099a11ec74381cf7876549e6402d776c068d4870be150342124130d054103c90985ad6ea4d }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
