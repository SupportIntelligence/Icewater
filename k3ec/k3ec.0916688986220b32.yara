
rule k3ec_0916688986220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.0916688986220b32"
     cluster="k3ec.0916688986220b32"
     cluster_size="7"
     filetype = "PE32 executable (console) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="brontok email pazetus"
     md5_hashes="['397d3faf6496ce3be17f6dbe657bbee2','49ec18d3b59899376e8bc6a1d3326288','d8cbce5aecaeff3355c546d74505d4f7']"

   strings:
      $hex_string = { 15bb82446df121fcd17be21ea8ecc1460d26483040b8087af4feeae583acc660846a52729db99736cbf02085294ceee0a19b5af12712dbe9b154edc42e93b538 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
