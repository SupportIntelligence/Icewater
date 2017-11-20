
rule k3e9_291ef3a9c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.291ef3a9c8000932"
     cluster="k3e9.291ef3a9c8000932"
     cluster_size="348"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy backdoor injector"
     md5_hashes="['036a7a177b6de69ea5441e814dcb8bb7','03dbd600ff411d7601ec622b430c7c40','22c2ca1f4295e4c721bf7bd37621101f']"

   strings:
      $hex_string = { 8847018a46028847028b45085e5fc9c3908d7431fc8d7c39fcf7c7030000007524c1e90283e20383f908720dfdf3a5fcff2495306840008bfff7d9ff248de067 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
