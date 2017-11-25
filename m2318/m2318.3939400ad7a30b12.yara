
rule m2318_3939400ad7a30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2318.3939400ad7a30b12"
     cluster="m2318.3939400ad7a30b12"
     cluster_size="51"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['092d97b08ccf4eef60f822b548262816','18cbd3644cd6743419e3ea7515182dc4','50d8da28697a4c62ae897c017da3d187']"

   strings:
      $hex_string = { 42364337453939353641333746414530344344303941453232384437443436314237314235423246383238393833364438354543344441354638334632333031 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
