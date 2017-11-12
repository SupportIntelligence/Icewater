
rule m3ed_531403b999346916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.531403b999346916"
     cluster="m3ed.531403b999346916"
     cluster_size="190"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bqjjnb"
     md5_hashes="['12bc029c73f4a8ca9508f387bd7ddd5f','16bf19fbcd0884a7f579b5a60155e922','5439d259399797454f7b70e19128b51e']"

   strings:
      $hex_string = { 6c30d130173288325d33ce338b351f36ec364337553722382a39763ae63a1d3b353b593c913c5f3dd73d063e3d3e4d3e893ef93e0000010048000000ab309a31 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
