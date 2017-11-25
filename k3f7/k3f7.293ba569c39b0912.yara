
rule k3f7_293ba569c39b0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.293ba569c39b0912"
     cluster="k3f7.293ba569c39b0912"
     cluster_size="20"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cryxos redirector iframe"
     md5_hashes="['00d989daeabd505641557bb61bf12c3b','091b7eb9a7c16b74b1d1b58af9dcfcd4','bb34888dc17a9b056301620eceb225de']"

   strings:
      $hex_string = { 4b51444a6441635875616d79626a537745506144434d756356624167494842566b734b4c6f65467c696672616d657c323570787c74737c765f63643066323964 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
