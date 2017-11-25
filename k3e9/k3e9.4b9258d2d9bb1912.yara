
rule k3e9_4b9258d2d9bb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4b9258d2d9bb1912"
     cluster="k3e9.4b9258d2d9bb1912"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ganelp autorun emailworm"
     md5_hashes="['315b63434b374e8c1325b64ccc39e064','3fb730b292bb8905c31b827521e919bc','f5bc6aff71f70339d23287e3eedfc4fc']"

   strings:
      $hex_string = { a0d734ae59bcf27eacb25ee8a7a3ad56524e1b3088e6db8f5b53172ed112618048d2009ae71c504852bf4a92460549c2bd9721daa9c1d967558b139929ef68c4 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
