
rule m3e9_6b2f0494c2210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6b2f0494c2210b12"
     cluster="m3e9.6b2f0494c2210b12"
     cluster_size="16"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod viking"
     md5_hashes="['0153da26985207161206c9ccb85b08f7','60ab531a9e266e6e89411bba5640450b','f2dae1a91a3444e5ff5e60e0eaf2164a']"

   strings:
      $hex_string = { c1ad5ed58f6d260c1f0d6fc4be8e0096b4998b7a6934ebae574635d00bc9401472a7b0e4eae79eb84536c6dff44c5955e9f95d900a60e5771788815606e0647f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
