
rule m2319_2b9b15e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.2b9b15e9c8800b12"
     cluster="m2319.2b9b15e9c8800b12"
     cluster_size="6"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker script"
     md5_hashes="['0ba2b072dde1b1618b326c067004caa1','127c6c0d0b05b0b9b8890e3b962a1fc5','fe7eb4c18172e023b5748e97d5ae162e']"

   strings:
      $hex_string = { 323031352f31302f342d72686f6c61732d6d6167617a696e652d70726f63652e68746d6c273e342052484f4c4153204d4147415a494e452050524f43c38a213c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
