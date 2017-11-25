
rule m3e9_13237cc3cc000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.13237cc3cc000932"
     cluster="m3e9.13237cc3cc000932"
     cluster_size="71"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installcore unwanted advml"
     md5_hashes="['009e2edfa9ab934ceca90aba52bfbfce','022cc5364cf9d10fd0e4e610c043eb4e','4e16b866a7414e2d1a9de83ec0322c37']"

   strings:
      $hex_string = { 1674dbbe474898bfde990249202fdf657d9e2a75eaf1b15db71d5b0d6dc273a3383e3637764570f8c4da2df94da1d913cf6b1030fbe954a22860696606ae6277 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
