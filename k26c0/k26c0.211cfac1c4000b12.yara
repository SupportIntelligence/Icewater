
rule k26c0_211cfac1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26c0.211cfac1c4000b12"
     cluster="k26c0.211cfac1c4000b12"
     cluster_size="510"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="backdoor bgtuw heuristic"
     md5_hashes="['67dee83cb5f7bf1fd64bb3e9bd4d29c7831f6256','4a838dee6f6bf90bad694c8aa9343d9a9bf6a6cd','f536897361efa419654e972e51d7bfee6ba8724e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26c0.211cfac1c4000b12"

   strings:
      $hex_string = { 020017058101130519001b0501181105070019050106150561001d0501601005040018050103140531001c05013012050d001a05010c1605c100400500001000 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
