
rule m3e9_124b30dbc6220916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.124b30dbc6220916"
     cluster="m3e9.124b30dbc6220916"
     cluster_size="168"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob patched"
     md5_hashes="['01454d7dd118272f6ef8f9a5f9a23e1e','0705747dd947620aabdce3425a8cf1fd','4e6ec2af44b585d7e907ccdb6e9472cc']"

   strings:
      $hex_string = { 37b6a8a4558b999765161c0b4b0f595f48b7a8a443899a9d094a1f065b1e354733b5a8a485709ea201574204081020271bafa87e7b6f6e795202a540111a2423 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
