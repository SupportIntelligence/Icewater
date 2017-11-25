
rule k3e9_091a9cc9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.091a9cc9cc000b12"
     cluster="k3e9.091a9cc9cc000b12"
     cluster_size="52"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="rincux ddos stormattack"
     md5_hashes="['06a7f417541b709eff1e4771817b56a7','094dfe21210db6993f4076abc92bb8a0','6ceb2b432ede8cc9db38995236077360']"

   strings:
      $hex_string = { b5987cfa67492a85cf5e8452a5b6188f305cda81959d6ddd331c5687173f4468da832861c0486021baf7f18b138c383ec9ea12d24c017962a93c65c77b1a6341 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
