
rule m3e9_29155466cd410b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.29155466cd410b32"
     cluster="m3e9.29155466cd410b32"
     cluster_size="45"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus symmi vbna"
     md5_hashes="['09fd1ef83e6f105f2a477e40b4a25264','0c406ea69a98cf26cdadd1fa2bb74ebc','a7342079e09b737cdc778a4c2ade7efb']"

   strings:
      $hex_string = { 814eaa7f4ca87e4ab2874bb08549b48d5bbb9669ae8245b6905db48d5ac6a166c5a065c49e62cdab71d0ac75ceab73d4af7dcba76ddac091e3ccaad9bc9bd3b7 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
