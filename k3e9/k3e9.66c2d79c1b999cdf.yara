
rule k3e9_66c2d79c1b999cdf
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.66c2d79c1b999cdf"
     cluster="k3e9.66c2d79c1b999cdf"
     cluster_size="129"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="adload nsis riskware"
     md5_hashes="['00baf865707b01b6155a1e30695ce3b7','07f22a860bf63a05835a2b733b48b400','28dcfd02e0694b1632ceb0e2f949a992']"

   strings:
      $hex_string = { 4c2418c1e0058db408180800008b461485c0742a6a1a593bc1742383f8ff7507e8dff0ffffeb2285c07e0e83f8197f094850e851f1ffffeb0f894e14eb0b6834 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
