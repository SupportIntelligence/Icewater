
rule m2321_4b95a4b2db9b0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.4b95a4b2db9b0912"
     cluster="m2321.4b95a4b2db9b0912"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor zusy shiz"
     md5_hashes="['030acccda1a29aca476ec2d45f4581a7','223c58d8375912ebefcaaa892614b1ae','51e768f23213442a3a629a054de778cf']"

   strings:
      $hex_string = { e4e7da86f9297ab825a987737f08090b1ea798b4942d266bb651ed59837dd3cb3dec6e2ce25db5a691240114f8636f215a02c312c9319922288b6c6df3f20dca }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
