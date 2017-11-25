
rule k3e9_63146fb11cca7b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146fb11cca7b16"
     cluster="k3e9.63146fb11cca7b16"
     cluster_size="53"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['0486aae4eea31108339588c804ae8953','144f957771b12512aa127d55bc824d3a','b28159aea483b8608b1bd03a0d65aa64']"

   strings:
      $hex_string = { 0077007300280054004d00290020004f007000650072006100740069006e0067002000530079007300740065006d0000003e000d000100500072006f00640075 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
