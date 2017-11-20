
rule m3e9_13636ed1c4000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.13636ed1c4000932"
     cluster="m3e9.13636ed1c4000932"
     cluster_size="38"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installcore malicious unwanted"
     md5_hashes="['0e5283e67353105ed69daeba0d001026','0fc968f2afd328cf133e5c9f8b17afa4','54808b6df047a15d3a76e8acdb5ee821']"

   strings:
      $hex_string = { 1674dbbe474898bfde990249202fdf657d9e2a75eaf1b15db71d5b0d6dc273a3383e3637764570f8c4da2df94da1d913cf6b1030fbe954a22860696606ae6277 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
