
rule k3e9_4b4626a4ee564c9a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4b4626a4ee564c9a"
     cluster="k3e9.4b4626a4ee564c9a"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob malicious"
     md5_hashes="['19b397760f852c316dd1d38f7e3d1acc','2f14191deb44c6b6a0a4864e7016be9e','a9b7a14b1dafff7181fae8a166cc8473']"

   strings:
      $hex_string = { 8a084084c975f92bc28bf083fe048bfe730433c0eb3e6a0b687c32000153ff155012000183c40c85c075058d46f6eb2485f67409803c1f5c74034f75f7b87cbd }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
