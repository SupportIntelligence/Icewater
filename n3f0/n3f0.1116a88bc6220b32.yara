
rule n3f0_1116a88bc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f0.1116a88bc6220b32"
     cluster="n3f0.1116a88bc6220b32"
     cluster_size="9467"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="autorun backdoor injector"
     md5_hashes="['00003f306b6c2c46bea1b9bd9c66a5fe','0002891481ec0980f879a4787d3f31c7','00a33e7cdf9a768d485eb928fff60bdf']"

   strings:
      $hex_string = { 0d82c1481fb7630239628b267a6c7c83623d6ecf7bdaa4d971f2b91e124c1be8253c7a7ad58a76b40d052744ec9e39614e675e4d2a8611a9681b9626510220cc }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
