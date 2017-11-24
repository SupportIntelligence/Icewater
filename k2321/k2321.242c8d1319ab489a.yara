
rule k2321_242c8d1319ab489a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.242c8d1319ab489a"
     cluster="k2321.242c8d1319ab489a"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dinwod kazy trojandropper"
     md5_hashes="['007ef61538a105dfc2801163006a50ef','17481c1c5a321c339b3ce05d2b0376c5','604683471158a52464242642772ccb59']"

   strings:
      $hex_string = { c7b3b6178ae90eeb3415e5cd25879bad429ef204fc84365d78039f1e4d49811f61d3cffdb28d6c7ebae8793e20ff777548d7fe802ddf1d749d147afbee990296 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
