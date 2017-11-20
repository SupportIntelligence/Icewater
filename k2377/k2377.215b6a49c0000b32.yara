
rule k2377_215b6a49c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2377.215b6a49c0000b32"
     cluster="k2377.215b6a49c0000b32"
     cluster_size="12"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="redirector cryxos html"
     md5_hashes="['2e30292411fb587bcc2af1fe297d6a73','34c7d3d18a7ca5126297e060300f0a8c','ee9a16ec19524a114a12582bbf618bd4']"

   strings:
      $hex_string = { 6e77746b3736676a293b2071636c3271203d20732e63686172436f646541742869293b7d207331203d2073312e7265706c616365282f5b5e612d7a412d5a302d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
