
rule k3e9_4b4626a4ee5e44fa
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4b4626a4ee5e44fa"
     cluster="k3e9.4b4626a4ee5e44fa"
     cluster_size="7"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob malicious"
     md5_hashes="['13eb114945af7512d326151e253aa253','1a2e9ade41953a49128f8e09be3cf4dd','d6668393628e1477aa8b0dcfdc4995e8']"

   strings:
      $hex_string = { 8a084084c975f92bc28bf083fe048bfe730433c0eb3e6a0b687c32000153ff155012000183c40c85c075058d46f6eb2485f67409803c1f5c74034f75f7b87cbd }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
