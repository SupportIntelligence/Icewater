
rule m2321_1992645adcbb0916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.1992645adcbb0916"
     cluster="m2321.1992645adcbb0916"
     cluster_size="85"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor elzob shiz"
     md5_hashes="['00024aab5c03daf2859197ecb401b7b4','01ffcc7ef700e7c4f46d2ca0e867dca5','2adfa2c719c287fe5abe6cedee34892c']"

   strings:
      $hex_string = { 4041c8f21fc95b1850a833afcef90f4dc093c62b94dbc525e1e37d3e207eb4d1d04776047121a465383c6670619dcddebe27c31217d98378061d84f6ffec44fb }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
