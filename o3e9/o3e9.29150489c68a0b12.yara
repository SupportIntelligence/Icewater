
rule o3e9_29150489c68a0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.29150489c68a0b12"
     cluster="o3e9.29150489c68a0b12"
     cluster_size="327"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="blackv malicious noobyprotect"
     md5_hashes="['00e817c37401cfce76a72311d6338bc2','00ebea633d1ba23d244ae66bb8c4296d','0e4e9833488c23cc8943642fdcc42e6d']"

   strings:
      $hex_string = { 95142a9d28161fb08c5f024d2a367d189cea6ea1a8dfb2a900d80a453f20d04357c8ced483ce98db9c37c0abe9be13f2c876733d8037718d3696b29e4bc86d9c }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
