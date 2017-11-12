
rule n3e9_4114d2c9c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4114d2c9c4000b32"
     cluster="n3e9.4114d2c9c4000b32"
     cluster_size="1000"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['003a17be93ddbe4ad5a77ccc551e6f55','00f797a04efc25862696109fc431e352','0c73b44a7ba57e4328d4bc3607c3d87e']"

   strings:
      $hex_string = { eaeaeaeaeaebeaebebebe7e9e9cdd3dda0b1cd6e8abd375fae1847ac0b3ead0b3eb00b3eaf0b3cab0b35a70b3aaa1c51ba3877d456a0ee68b6fc6ebefe6ab8fd }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
