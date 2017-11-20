
rule k2321_0917688986220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.0917688986220b12"
     cluster="k2321.0917688986220b12"
     cluster_size="15"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="brontok email pazetus"
     md5_hashes="['03ed05d39b2de67e5a0b392edf8be097','18a07827ae3650bf9c6afe62f2ac3c8e','d82f22da9b73edc72de19770dc84d316']"

   strings:
      $hex_string = { 15bb82446df121fcd17be21ea8ecc1460d26483040b8087af4feeae583acc660846a52729db99736cbf02085294ceee0a19b5af12712dbe9b154edc42e93b538 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
