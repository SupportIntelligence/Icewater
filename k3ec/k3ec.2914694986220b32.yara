
rule k3ec_2914694986220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.2914694986220b32"
     cluster="k3ec.2914694986220b32"
     cluster_size="24"
     filetype = "PE32 executable (console) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hackkms risktool uvpm"
     md5_hashes="['0c0931899fe39690b3f30c531cb67b6c','224cb49ccbf71403746ae4d622e1135b','bf446ec419011d7c5ec4679d6aa0caa0']"

   strings:
      $hex_string = { a6b416926bf7e82b5271969e8518bf200f1bb2d63aa1c986f1a0b3e5784a4ef391a4fd8a28e46cefd79db5fa15ccee4a7b697e3f5b58ecd355b1afea9fc499e3 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
