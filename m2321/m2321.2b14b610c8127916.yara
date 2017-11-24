
rule m2321_2b14b610c8127916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.2b14b610c8127916"
     cluster="m2321.2b14b610c8127916"
     cluster_size="8"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['0306a06ec712b2628481fd33ca383ff4','0b5aa0dfe27292985bcb7a852e20f40e','f15ce4d319a99855c92f65fd313181b0']"

   strings:
      $hex_string = { 534b3a671e5e5fc086a042d5a47e2baf2697d90e8bc3d443606147921fce7ba6c82182238a524fa1dd9d28738ecc912c62311dc9bbe9d6362f04f57a3d19b3e8 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
