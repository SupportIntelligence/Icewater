
rule o26bb_4c83a949c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.4c83a949c4000b12"
     cluster="o26bb.4c83a949c4000b12"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dealply malicious clmqn"
     md5_hashes="['6d5f75692908048b946903a20e9562f01dd04516','fa916dfa489ff7405b24589e87387370ef3442f5','acf774358365b0fd141a80e481245e1354bd835c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.4c83a949c4000b12"

   strings:
      $hex_string = { 88c5d26008370002837b9bd067c722606a2da2e25815cc70771309b4a8ff63abe89e1d12749d23508a7581d97ea6cbd074490dbd013da34b097d32c38d40009f }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
