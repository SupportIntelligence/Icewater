
rule n2706_42549499ea210b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2706.42549499ea210b14"
     cluster="n2706.42549499ea210b14"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="browsefox ursu malicious"
     md5_hashes="['b748624a0b4feca244eed850c34c9b9602948039','322c9e4c293b9bf83f7eb9a46b63e729b8bca4c6','6ccc78a9024a88e1dcb521b96772702643cfae3e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2706.42549499ea210b14"

   strings:
      $hex_string = { 3737393162646131613330383934366563323534663000457175616c73006f626a0066756e6374696f6e006100620047657448617368436f6465006f705f4571 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
