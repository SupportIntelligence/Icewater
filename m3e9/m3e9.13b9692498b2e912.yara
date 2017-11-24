
rule m3e9_13b9692498b2e912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.13b9692498b2e912"
     cluster="m3e9.13b9692498b2e912"
     cluster_size="112"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shipup lethic zbot"
     md5_hashes="['05aac8fc91980db9231e71437c40aedb','08310fe989b2ebb2a5425ff2e7f98b7a','56830ad921e4c24e508114b693e851c8']"

   strings:
      $hex_string = { ad73045b51d2134b1eee09d1a9a057b0106e2483b3404d00ebf29ef5b7011d39bdd52a59a8af4e5c1ad9865d674847f95e2d7cd79df6684c1b5a89ed3d78ec56 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
