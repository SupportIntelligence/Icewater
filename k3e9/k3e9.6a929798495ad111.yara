
rule k3e9_6a929798495ad111
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6a929798495ad111"
     cluster="k3e9.6a929798495ad111"
     cluster_size="5"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="adload nsis malicious"
     md5_hashes="['08f3132f217194aee99a18cad199fa60','56297f5f57e9566b843a7b9b022a9680','def16c15ab6015e8ccfd8e16a5b2638b']"

   strings:
      $hex_string = { 4c2418c1e0058db408180800008b461485c0742a6a1a593bc1742383f8ff7507e8dff0ffffeb2285c07e0e83f8197f094850e851f1ffffeb0f894e14eb0b6834 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
