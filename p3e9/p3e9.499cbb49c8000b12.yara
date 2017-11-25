
rule p3e9_499cbb49c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p3e9.499cbb49c8000b12"
     cluster="p3e9.499cbb49c8000b12"
     cluster_size="12"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock nabucur cryptor"
     md5_hashes="['32d5429b8738f602f098756456b8d97a','50538fdc4ac59c0addb3d456063193e8','e31ac8fb2caf718093c52adc17450e18']"

   strings:
      $hex_string = { 3e02fbfbf97994a8f2ff0838f5ff325bfeff5376feff738efeff8ba3f8ffa4b4ecffb6bcdfffbcc6d4ffafd7caff8edcbeff4ad29cff0fbc79ff00a76bff0398 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
