
rule m3e9_2b95a4b2db9b0916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2b95a4b2db9b0916"
     cluster="m3e9.2b95a4b2db9b0916"
     cluster_size="10"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor shiz zusy"
     md5_hashes="['12d493d5d8711c35733af9f6c5e47350','4985c14fd500172de5cb8918eff54e93','ecb521f1a38e44cceafc1f4df7dcfb44']"

   strings:
      $hex_string = { e4e7da86f9297ab825a987737f08090b1ea798b4942d266bb651ed59837dd3cb3dec6e2ce25db5a691240114f8636f215a02c312c9319922288b6c6df3f20dca }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
