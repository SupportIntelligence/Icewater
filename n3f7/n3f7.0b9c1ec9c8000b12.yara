
rule n3f7_0b9c1ec9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f7.0b9c1ec9c8000b12"
     cluster="n3f7.0b9c1ec9c8000b12"
     cluster_size="22"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html inor"
     md5_hashes="['0a268eedcf5e54e2da912fb1f5db6b33','0f199e30a4047e1b210347e47215689b','ad34298ac6f317567719fc786c8aeab5']"

   strings:
      $hex_string = { 42364337453939353641333746414530344344303941453232384437443436314237314235423246383238393833364438354543344441354638334632333031 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
