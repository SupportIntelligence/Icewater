
rule m3e9_6314a5a0d99b0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6314a5a0d99b0912"
     cluster="m3e9.6314a5a0d99b0912"
     cluster_size="10"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple rahack malicious"
     md5_hashes="['4b3f3722861d8a76404fa0e4c92be9b6','88c50f10d0be0347d7ec589aa8a46564','f83ba328ea4333f836209e8813a23cc8']"

   strings:
      $hex_string = { 5613941120378d19e6222376fe88342a9ffb79787b5bb8d2698eba5a8bf626d0a05dd9933e47b1e78cc97d977cd506fc8f921066cef9f239028090ad09c76d45 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
