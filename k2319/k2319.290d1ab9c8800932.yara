
rule k2319_290d1ab9c8800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.290d1ab9c8800932"
     cluster="k2319.290d1ab9c8800932"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['3fb775360551388c8bc86268713ee2296a5cebe8','b1d3ec7c059ae474db248bac421eac1177506663','c6b1ad2adccd4b3280065ee85d0bfd21f356a49c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.290d1ab9c8800932"

   strings:
      $hex_string = { 7b76617220713d28585b282263686172436f64222b2265417422295d286c2926282835322e3245312c3078323146293c307837423f342e3445323a2837392e38 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
