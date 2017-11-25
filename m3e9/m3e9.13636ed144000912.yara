
rule m3e9_13636ed144000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.13636ed144000912"
     cluster="m3e9.13636ed144000912"
     cluster_size="45"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installcore malicious unwantedsig"
     md5_hashes="['02e3c227e5d8da128d1a32c2b8cece82','0604174727bcb3d3a123e307001db815','70bebe66feb67308c2770d1b9d8f7a87']"

   strings:
      $hex_string = { 1674dbbe474898bfde990249202fdf657d9e2a75eaf1b15db71d5b0d6dc273a3383e3637764570f8c4da2df94da1d913cf6b1030fbe954a22860696606ae6277 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
