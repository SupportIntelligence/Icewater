
rule m3ec_51b5c66913d30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ec.51b5c66913d30932"
     cluster="m3ec.51b5c66913d30932"
     cluster_size="163"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['0010f6275c92019fca0b14002070b311','00197324e09d44c28588e132c7a01a61','1250befc55d5b8e2fd57a2ee36fe75fd']"

   strings:
      $hex_string = { 00018945f83bc77513ff15d410000185c0740950e8a8a1ffff59ebcf8bc683e61f6bf624c1f8058b0485400202018d4430048020fd8b45f88b55fc5f5ec9c3cc }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
