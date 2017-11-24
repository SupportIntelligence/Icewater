
rule k3ec_2b14e08982220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.2b14e08982220b12"
     cluster="k3ec.2b14e08982220b12"
     cluster_size="7"
     filetype = "PE32 executable (console) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="brontok email pazetus"
     md5_hashes="['295de7470f4ceb1a3a27382cd670cff2','53f0e6a3bbb5c25bf94909844042cf7f','ec7469336df091aa5799cddaae713c3b']"

   strings:
      $hex_string = { 82877379112e957407c8606e97a69b0e0c1b271eaa31ad6915e7ffaa647a54f2bd0a5d74fe2b484233618e3e86c05cea1fdfc3777c6d9f056a76b3013cae203d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
