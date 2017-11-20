
rule m2321_1a58c868d912f912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.1a58c868d912f912"
     cluster="m2321.1a58c868d912f912"
     cluster_size="10"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="carberp shiz kazy"
     md5_hashes="['1ecb14813757e9374bf26eff88172eac','2b0e827ce575304c2ca99b32c96790f6','f19d9c420fd26194e40bc8cc8821501c']"

   strings:
      $hex_string = { 214b290ebf80f719cb6625dfbea7ca69337ebd35ce9da9b3d755f8537be46343858358883a0b93b73c55edd4c34dd502622a4c2227901fc4d9c90756bb896416 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
