
rule k3f7_293b25e9c39b0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.293b25e9c39b0912"
     cluster="k3f7.293b25e9c39b0912"
     cluster_size="9"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="redirector iframe redir"
     md5_hashes="['1641cc697c824e3ce20917fc11f179f3','6d3c21ea2b790ad85e419e5c160ecd4b','dedf840b2a3a4f3434116ec1455efa10']"

   strings:
      $hex_string = { 4b51444a6441635875616d79626a537745506144434d756356624167494842566b734b4c6f65467c696672616d657c323570787c74737c765f63643066323964 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
