
rule n3f4_399a1ec1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f4.399a1ec1c8000b12"
     cluster="n3f4.399a1ec1c8000b12"
     cluster_size="9"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="msilperseus malicious eorezo"
     md5_hashes="['05ee9ccf1e742a439cf8cf56af46f93a','21bbfa6b911fa37a509807bf6c3ad88a','f1e9b6ebfcb2f98e70b7cb4468cb609b']"

   strings:
      $hex_string = { 57696e646f7773c2a0382e31202d2d3e0d0a2020202020203c212d2d3c737570706f727465644f532049643d227b31663637366337362d383065312d34323339 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
