
rule k2321_13159a50da227916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.13159a50da227916"
     cluster="k2321.13159a50da227916"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma rontokbro"
     md5_hashes="['0f0f2f2c5422f6680470881cc5639997','8f300a0e57531c6e67eec699eb187ce9','ff5ca0565d00a3627e2dffb32c4e90de']"

   strings:
      $hex_string = { 5c71ecf6894d4a25eee9bb128f572a3d10898349c5313e7cb79295a1be0406af1b5815873740439d47f75b5ea3fec23f632b59ebdaea66bf1eae560e17dd4e38 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
